import pytest


@pytest.fixture(scope="module")
def pqc_openssl():
    """Only real PQC integration tests require this optional executable."""
    from pqc_lab import lab

    try:
        return lab.find_openssl()
    except RuntimeError as exc:
        pytest.skip(str(exc))
