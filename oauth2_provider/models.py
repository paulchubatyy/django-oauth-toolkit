import logging
import time
import uuid
from datetime import timedelta
from urllib.parse import parse_qsl, urlparse

from django.apps import apps
from django.conf import settings
from django.contrib.auth.hashers import identify_hasher, make_password
from django.core.exceptions import ImproperlyConfigured
from django.db import models, transaction
from django.urls import reverse
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from jwcrypto import jwk
from jwcrypto.common import base64url_encode
from oauthlib.oauth2.rfc6749 import errors

from .generators import generate_client_id, generate_client_secret
from .scopes import get_scopes_backend
from .settings import oauth2_settings
from .utils import jwk_from_pem
from .validators import AllowedURIValidator


logger = logging.getLogger(__name__)


class ClientSecretField(models.CharField):
    def pre_save(self, model_instance, add):
        secret = getattr(model_instance, self.attname)
        should_be_hashed = getattr(model_instance, "hash_client_secret", True)
        if not should_be_hashed:
            return super().pre_save(model_instance, add)

        try:
            hasher = identify_hasher(secret)
            logger.debug(f"{model_instance}: {self.attname} is already hashed with {hasher}.")
        except ValueError:
            logger.debug(f"{model_instance}: {self.attname} is not hashed; hashing it now.")
            hashed_secret = make_password(secret)
            setattr(model_instance, self.attname, hashed_secret)
            return hashed_secret
        return super().pre_save(model_instance, add)


def get_application_model():
    """Return the Application model that is active in this project."""
    return apps.get_model(oauth2_settings.APPLICATION_MODEL)


def get_grant_model():
    """Return the Grant model that is active in this project."""
    return apps.get_model(oauth2_settings.GRANT_MODEL)


def get_access_token_model():
    """Return the AccessToken model that is active in this project."""
    return apps.get_model(oauth2_settings.ACCESS_TOKEN_MODEL)


def get_id_token_model():
    """Return the AccessToken model that is active in this project."""
    return apps.get_model(oauth2_settings.ID_TOKEN_MODEL)


def get_refresh_token_model():
    """Return the RefreshToken model that is active in this project."""
    return apps.get_model(oauth2_settings.REFRESH_TOKEN_MODEL)


def get_application_admin_class():
    """Return the Application admin class that is active in this project."""
    application_admin_class = oauth2_settings.APPLICATION_ADMIN_CLASS
    return application_admin_class


def get_access_token_admin_class():
    """Return the AccessToken admin class that is active in this project."""
    access_token_admin_class = oauth2_settings.ACCESS_TOKEN_ADMIN_CLASS
    return access_token_admin_class


def get_grant_admin_class():
    """Return the Grant admin class that is active in this project."""
    grant_admin_class = oauth2_settings.GRANT_ADMIN_CLASS
    return grant_admin_class


def get_id_token_admin_class():
    """Return the IDToken admin class that is active in this project."""
    id_token_admin_class = oauth2_settings.ID_TOKEN_ADMIN_CLASS
    return id_token_admin_class


def get_refresh_token_admin_class():
    """Return the RefreshToken admin class that is active in this project."""
    refresh_token_admin_class = oauth2_settings.REFRESH_TOKEN_ADMIN_CLASS
    return refresh_token_admin_class


def clear_expired():
    def batch_delete(queryset, query):
        CLEAR_EXPIRED_TOKENS_BATCH_SIZE = oauth2_settings.CLEAR_EXPIRED_TOKENS_BATCH_SIZE
        CLEAR_EXPIRED_TOKENS_BATCH_INTERVAL = oauth2_settings.CLEAR_EXPIRED_TOKENS_BATCH_INTERVAL
        current_no = start_no = queryset.count()

        while current_no:
            flat_queryset = queryset.values_list("id", flat=True)[:CLEAR_EXPIRED_TOKENS_BATCH_SIZE]
            batch_length = flat_queryset.count()
            queryset.model.objects.filter(id__in=list(flat_queryset)).delete()
            logger.debug(f"{batch_length} tokens deleted, {current_no-batch_length} left")
            queryset = queryset.model.objects.filter(query)
            time.sleep(CLEAR_EXPIRED_TOKENS_BATCH_INTERVAL)
            current_no = queryset.count()

        stop_no = queryset.model.objects.filter(query).count()
        deleted = start_no - stop_no
        return deleted

    now = timezone.now()
    refresh_expire_at = None
    access_token_model = get_access_token_model()
    refresh_token_model = get_refresh_token_model()
    id_token_model = get_id_token_model()
    grant_model = get_grant_model()
    REFRESH_TOKEN_EXPIRE_SECONDS = oauth2_settings.REFRESH_TOKEN_EXPIRE_SECONDS

    if REFRESH_TOKEN_EXPIRE_SECONDS:
        if not isinstance(REFRESH_TOKEN_EXPIRE_SECONDS, timedelta):
            try:
                REFRESH_TOKEN_EXPIRE_SECONDS = timedelta(seconds=REFRESH_TOKEN_EXPIRE_SECONDS)
            except TypeError:
                e = "REFRESH_TOKEN_EXPIRE_SECONDS must be either a timedelta or seconds"
                raise ImproperlyConfigured(e)
        refresh_expire_at = now - REFRESH_TOKEN_EXPIRE_SECONDS

    if refresh_expire_at:
        revoked_query = models.Q(revoked__lt=refresh_expire_at)
        revoked = refresh_token_model.objects.filter(revoked_query)

        revoked_deleted_no = batch_delete(revoked, revoked_query)
        logger.info("%s Revoked refresh tokens deleted", revoked_deleted_no)

        expired_query = models.Q(access_token__expires__lt=refresh_expire_at)
        expired = refresh_token_model.objects.filter(expired_query)

        expired_deleted_no = batch_delete(expired, expired_query)
        logger.info("%s Expired refresh tokens deleted", expired_deleted_no)
    else:
        logger.info("refresh_expire_at is %s. No refresh tokens deleted.", refresh_expire_at)

    access_token_query = models.Q(refresh_token__isnull=True, expires__lt=now)
    access_tokens = access_token_model.objects.filter(access_token_query)

    access_tokens_delete_no = batch_delete(access_tokens, access_token_query)
    logger.info("%s Expired access tokens deleted", access_tokens_delete_no)

    id_token_query = models.Q(access_token__isnull=True, expires__lt=now)
    id_tokens = id_token_model.objects.filter(id_token_query)

    id_tokens_delete_no = batch_delete(id_tokens, id_token_query)
    logger.info("%s Expired ID tokens deleted", id_tokens_delete_no)

    grants_query = models.Q(expires__lt=now)
    grants = grant_model.objects.filter(grants_query)

    grants_deleted_no = batch_delete(grants, grants_query)
    logger.info("%s Expired grant tokens deleted", grants_deleted_no)


def redirect_to_uri_allowed(uri, allowed_uris):
    """
    Checks if a given uri can be redirected to based on the provided allowed_uris configuration.

    On top of exact matches, this function also handles loopback IPs based on RFC 8252.

    :param uri: URI to check
    :param allowed_uris: A list of URIs that are allowed
    """

    parsed_uri = urlparse(uri)
    uqs_set = set(parse_qsl(parsed_uri.query))
    for allowed_uri in allowed_uris:
        parsed_allowed_uri = urlparse(allowed_uri)

        # From RFC 8252 (Section 7.3)
        #
        # Loopback redirect URIs use the "http" scheme
        # [...]
        # The authorization server MUST allow any port to be specified at the
        # time of the request for loopback IP redirect URIs, to accommodate
        # clients that obtain an available ephemeral port from the operating
        # system at the time of the request.

        allowed_uri_is_loopback = (
            parsed_allowed_uri.scheme == "http"
            and parsed_allowed_uri.hostname in ["127.0.0.1", "::1"]
            and parsed_allowed_uri.port is None
        )
        if (
            allowed_uri_is_loopback
            and parsed_allowed_uri.scheme == parsed_uri.scheme
            and parsed_allowed_uri.hostname == parsed_uri.hostname
            and parsed_allowed_uri.path == parsed_uri.path
        ) or (
            parsed_allowed_uri.scheme == parsed_uri.scheme
            and parsed_allowed_uri.netloc == parsed_uri.netloc
            and parsed_allowed_uri.path == parsed_uri.path
        ):
            aqs_set = set(parse_qsl(parsed_allowed_uri.query))
            if aqs_set.issubset(uqs_set):
                return True

    return False


def is_origin_allowed(origin, allowed_origins):
    """
    Checks if a given origin uri is allowed based on the provided allowed_origins configuration.

    :param origin: Origin URI to check
    :param allowed_origins: A list of Origin URIs that are allowed
    """

    parsed_origin = urlparse(origin)

    if parsed_origin.scheme not in oauth2_settings.ALLOWED_SCHEMES:
        return False

    for allowed_origin in allowed_origins:
        parsed_allowed_origin = urlparse(allowed_origin)
        if (
            parsed_allowed_origin.scheme == parsed_origin.scheme
            and parsed_allowed_origin.netloc == parsed_origin.netloc
        ):
            return True
    return False
