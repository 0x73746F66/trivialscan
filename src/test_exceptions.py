import pytest
from trivialscan import exceptions

def test_openssl_errno():
    openssl_errno = 18
    with pytest.raises(exceptions.ValidationError):
        raise exceptions.ValidationError(openssl_errno=openssl_errno)
