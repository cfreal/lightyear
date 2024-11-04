"""Filter chains that divide the space in two.

Each entry is: base: (yes, no, filters)

It means: if the character is in `base`, and the `filters`, after a dechunk, empty the
input, then the character is in `yes`, otherwise it is in `no`.

The storage is not efficient, but who cares. It is meant for humans to understand and
mentally parse easily.
"""

__all__ = ["DIGIT_SPLITTERS"]

DIGIT_SPLITTERS = {
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/": (
        "ahiqrstABDFGHQRSTUVWXZ0123456789",
        "bcdefgjklmnopuvwxyzCEIJKLMNOPY+/",
        "convert.iconv.IBM1141.IBM4517%2F%2FTRANSLIT%2F%2FIGNORE|convert.iconv.VISCII.MSZ_7795.3%2F%2FTRANSLIT%2F%2FIGNORE",
    ),
    "ahiqrstABDFGHQRSTUVWXZ0123456789": (
        "aiABDF0123456789",
        "hqrstGHQRSTUVWXZ",
        "convert.iconv.IBM284.IBM278",
    ),
    "bcdefgjklmnopuvwxyzCEIJKLMNOPY+/": (
        "cjklmnopuvwxzCJ",
        "bdefgyEIKLMNOPY+/",
        "convert.iconv.L1.UTF16LE|convert.iconv.IBM1122.IBM273|convert.quoted-printable-encode|convert.base64-encode|convert.iconv.IBM297.IBM280",
    ),
    "hqrstGHQRSTUVWXZ": (
        "hqrstGRS",
        "HQTUVWXZ",
        "convert.iconv.IBM273.IT%2F%2FTRANSLIT",
    ),
    "cjklmnopuvwxzCJ": (
        "lmnouvw",
        "cjkpxzCJ",
        "convert.iconv.L1.UTF16LE|convert.quoted-printable-encode|convert.base64-encode|convert.iconv.IBM273.CWI%2F%2FTRANSLIT",
    ),
    "bdefgyEIKLMNOPY+/": (
        "yEIKLMNO",
        "bdefgPY+/",
        "convert.iconv.L1.UTF16LE|convert.quoted-printable-encode|convert.base64-encode|convert.iconv.IBM273.ES%2F%2FTRANSLIT",
    ),
    "hqrstGRS": ("rtGR", "hqsS", "convert.iconv.IBM037.CP1250%2F%2FTRANSLIT"),
    "HQTUVWXZ": (
        "HQWX",
        "TUVZ",
        "convert.iconv.IBM277.ISO-8859-9E%2F%2FTRANSLIT|convert.iconv.CSN_369103.CP770%2F%2FTRANSLIT",
    ),
    "lmnouvw": (
        "uvw",
        "lmno",
        "convert.iconv.L1.UTF16LE|convert.quoted-printable-encode|convert.base64-encode|convert.iconv.IBM037.CP1250%2F%2FTRANSLIT",
    ),
    "cjkpxzCJ": (
        "jkxz",
        "cpCJ",
        "convert.iconv.L1.UTF16LE|convert.quoted-printable-encode|convert.base64-encode|convert.iconv.IBM037.IBM273",
    ),
    "bdefgPY+/": ("bde/", "fgPY+", "convert.iconv.ES.IBM930"),
    "yEIKLMNO": (
        "yEIK",
        "LMNO",
        "convert.iconv.L1.UTF16LE|convert.quoted-printable-encode|convert.base64-encode|convert.iconv.IBM273.IT%2F%2FTRANSLIT",
    ),
    "HQWX": ("HQ", "WX", "convert.iconv.IBM273.US%2F%2FTRANSLIT"),
    "hqsS": ("sS", "hq", "convert.iconv.IBM037.IBM860%2F%2FTRANSLIT"),
    "rtGR": ("rt", "GR", "convert.iconv.IBM273.CWI%2F%2FTRANSLIT"),
    "bde/": ("bd", "e/", "convert.iconv.IBM273.CWI%2F%2FTRANSLIT"),
    "yEIK": ("yE", "IK", "convert.iconv.IBM278.MIK%2F%2FTRANSLIT"),
    "lmno": (
        "lm",
        "no",
        "convert.iconv.L1.UTF16LE|convert.quoted-printable-encode|convert.base64-encode|convert.iconv.UTF16LE.UTF16BE|convert.iconv.IBM037.ES%2F%2FTRANSLIT",
    ),
    "cpCJ": ("cC", "pJ", "convert.iconv.IBM037.IBM256"),
    "fgPY+": ("fg", "PY+", "convert.iconv.IBM1390.IBM932"),
    "jkxz": (
        "xz",
        "jk",
        "convert.iconv.L1.UTF16LE|convert.quoted-printable-encode|convert.base64-encode|convert.iconv.IBM1390.SJIS%2F%2FTRANSLIT",
    ),
    "sS": ("s", "S", "convert.iconv.IBM273.CWI%2F%2FTRANSLIT"),
    "rt": ("r", "t", "convert.iconv.IBM870.MAC-IS%2F%2FTRANSLIT"),
    "uvw": (
        "w",
        "uv",
        "convert.iconv.IBM1149.MAC-SAMI%2F%2FTRANSLIT|convert.iconv.IBM278.IBM297",
    ),
    "TUVZ": (
        "UV",
        "TZ",
        "convert.iconv.IBM1148.EBCDIC-AT-DE-A%2F%2FTRANSLIT|convert.iconv.CWI.IT%2F%2FTRANSLIT",
    ),
    "yE": ("E", "y", "convert.iconv.IBM037.IBM256"),
    "LMNO": (
        "LM",
        "NO",
        "convert.iconv.L1.UTF16LE|convert.quoted-printable-encode|convert.base64-encode|convert.iconv.UTF16LE.UTF16BE|convert.iconv.IBM037.ES%2F%2FTRANSLIT",
    ),
    "hq": ("q", "h", "convert.iconv.IBM273.PT%2F%2FTRANSLIT"),
    "HQ": ("Q", "H", "convert.iconv.IBM297.IBM273"),
    "GR": ("G", "R", "convert.iconv.IBM1399.IBM930"),
    "IK": ("I", "K", "convert.iconv.IBM870.MAC-IS%2F%2FTRANSLIT"),
    "bd": ("d", "b", "convert.iconv.IBM037.CP1250%2F%2FTRANSLIT"),
    "WX": (
        "X",
        "W",
        "convert.iconv.L1.UTF16LE|convert.quoted-printable-encode|convert.base64-encode|convert.iconv.UTF16LE.UTF16BE",
    ),
    "e/": ("/", "e", "convert.iconv.ES.IBM037"),
    "pJ": ("J", "p", "convert.iconv.IBM256.IBM273"),
    "cC": ("c", "C", "convert.iconv.ES.IBM930"),
    "fg": ("f", "g", "convert.iconv.IBM037.IBM256"),
    "lm": (
        "l",
        "m",
        "convert.iconv.L1.UTF16LE|convert.quoted-printable-encode|convert.base64-encode|convert.iconv.UTF16LE.UTF16BE",
    ),
    "TZ": ("T", "Z", "convert.iconv.IBM273.ES%2F%2FTRANSLIT"),
    "no": (
        "n",
        "o",
        "convert.iconv.L1.UTF16LE|convert.quoted-printable-encode|convert.base64-encode|convert.iconv.UTF16LE.UTF16BE|convert.iconv.IBM1097.IBM918%2F%2FTRANSLIT",
    ),
    "jk": (
        "j",
        "k",
        "convert.iconv.L1.UTF16LE|convert.quoted-printable-encode|convert.base64-encode|convert.iconv.UTF16LE.UTF16BE|convert.iconv.IBM1097.IBM918%2F%2FTRANSLIT",
    ),
    "xz": (
        "x",
        "z",
        "convert.iconv.L1.UTF16LE|convert.quoted-printable-encode|convert.base64-encode|convert.iconv.UTF16LE.UTF16BE",
    ),
    "uv": (
        "u",
        "v",
        "convert.iconv.L1.UTF16LE|convert.quoted-printable-encode|convert.base64-encode|convert.iconv.UTF16LE.UTF16BE|convert.iconv.IBM037.ES%2F%2FTRANSLIT",
    ),
    "UV": (
        "U",
        "V",
        "convert.iconv.L1.UTF16LE|convert.quoted-printable-encode|convert.base64-encode|convert.iconv.UTF16LE.UTF16BE|convert.iconv.IBM037.ES%2F%2FTRANSLIT",
    ),
    "LM": (
        "L",
        "M",
        "convert.iconv.L1.UTF16LE|convert.quoted-printable-encode|convert.base64-encode|convert.iconv.UTF16LE.UTF16BE",
    ),
    "NO": (
        "N",
        "O",
        "convert.iconv.L1.UTF16LE|convert.quoted-printable-encode|convert.base64-encode|convert.iconv.UTF16LE.UTF16BE|convert.iconv.IBM1097.IBM918%2F%2FTRANSLIT",
    ),
    "PY+": (
        "Y",
        "P+",
        "convert.iconv.IBM278.IBM861%2F%2FTRANSLIT|convert.iconv.L1.IBM037",
    ),
    "P+": (
        "P",
        "+",
        "convert.iconv.L1.UTF16LE|convert.quoted-printable-encode|convert.base64-encode|convert.iconv.UTF16LE.UTF16BE",
    ),
    "aiABDF0123456789": (
        "aiABDF27",
        "01345689",
        "convert.iconv.IBM1145.IBM850%2F%2FTRANSLIT%2F%2FIGNORE|convert.iconv.IBM850.IBM278",
    ),
    "aiABDF27": (
        "aA27",
        "iBDF",
        "convert.iconv.IBM273.IBM420%2F%2FTRANSLIT%2F%2FIGNORE",
    ),
    "01345689": (
        "3456",
        "0189",
        "convert.iconv.IBM4971.ARMSCII-8%2F%2FTRANSLIT%2F%2FIGNORE|convert.iconv.CP737.IBM4971",
    ),
    "iBDF": ("BF", "iD", "convert.iconv.IBM037.IBM280"),
    "aA27": (
        "aA",
        "27",
        "convert.iconv.L1.UTF16LE|convert.quoted-printable-encode|convert.base64-encode|convert.iconv.UTF16LE.UTF16BE|convert.iconv.IBM037.ES%2F%2FTRANSLIT%2F%2FIGNORE",
    ),
    "3456": (
        "45",
        "36",
        "convert.iconv.L1.UTF16LE|convert.quoted-printable-encode|convert.base64-encode|convert.iconv.UTF16LE.UTF16BE|convert.iconv.IBM037.ES%2F%2FTRANSLIT%2F%2FIGNORE",
    ),
    "iD": ("D", "i", "convert.iconv.IBM037.IBM256"),
    "0189": (
        "08",
        "19",
        "convert.iconv.L1.UTF16LE|convert.quoted-printable-encode|convert.base64-encode|convert.iconv.UTF16LE.UTF16BE",
    ),
    "BF": ("B", "F", "convert.iconv.IBM1390.IBM939"),
    "aA": ("a", "A", "convert.iconv.ES.IBM930"),
    "27": (
        "2",
        "7",
        "convert.iconv.L1.UTF16LE|convert.quoted-printable-encode|convert.base64-encode|convert.iconv.UTF16LE.UTF16BE|convert.iconv.IBM1097.IBM918%2F%2FTRANSLIT%2F%2FIGNORE",
    ),
    "45": (
        "4",
        "5",
        "convert.iconv.L1.UTF16LE|convert.quoted-printable-encode|convert.base64-encode|convert.iconv.UTF16LE.UTF16BE",
    ),
    "36": (
        "6",
        "3",
        "convert.iconv.L1.UTF16LE|convert.quoted-printable-encode|convert.base64-encode|convert.iconv.UTF16LE.UTF16BE|convert.iconv.IBM1097.IBM918%2F%2FTRANSLIT%2F%2FIGNORE",
    ),
    "08": (
        "0",
        "8",
        "convert.iconv.IBM1137.8859_1%2F%2FTRANSLIT%2F%2FIGNORE|convert.iconv.IBM280.IBM273",
    ),
    "19": (
        "1",
        "9",
        "convert.iconv.IBM1141.8859_1|convert.iconv.IBM860.MIK%2F%2FTRANSLIT%2F%2FIGNORE",
    ),
}
