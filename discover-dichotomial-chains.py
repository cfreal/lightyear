#!/usr/bin/env python3

"""
This script tries to find filters and charset conversions that divide a set of base64
digits in two:

- one set that contains digits that become hex digits after the conversion;
- another set that contains digits that do not.
"""
# TODO The check for translit//ignore does not always work
# TODO We may not need //ignore, only //translit
# TODO Add technique with L1.UCS4 as well?

from __future__ import annotations

import random
import string
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, replace
from itertools import product


from ten import *
from iconv import convert

# import iconv # memleak lol

LOG = logger("sorrow")

# Constants

HEXDIGITS = string.hexdigits.encode()
BASE64_DIGITS = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/"

QPE_UNCONVERTED_BYTES = b"\t !\"#$%&'()*+,-./0123456789:;<>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~"
STOP = False
BLOCKING: bytes = b"\r\n"
"""Bytes that we cannot afford to have in the final state, as they would break the
dechunk operation.
"""
BASE64_CONVERTING_CHARSETS = []
"""Charsets that can convert base64 digits to something else. Gets filled in main()."""

CHARSETS = table.read("./charsets.list")

# Typing

Char = bytes
Chain = tuple[Char, ...]
Digit = str
Byte = bytes
Conversion = tuple[str, str]
FilterChain = list[str]
Translations = dict[Char, dict[Char, list[Conversion]]]


# Useful filters

B64E = "convert.base64-encode"
SWAP2 = "convert.iconv.UTF16LE.UTF16BE"
SWAP4 = "convert.iconv.UCS-4LE.UCS-4BE"
QPE = "convert.quoted-printable-encode"


@entry
def main(
    base_state: str = BASE64_DIGITS.decode(),
    timeout: int = 60,
    recave: int = 10,
    workers: int = 16,
) -> None:
    global STOP
    # The filter chains will get stored there
    storage = Path(f"./chains/chain-{tf.random.string()}.py")
    storage.parent.mkdir(exist_ok=True)
    msg_info(f"Storing chains in [b]{storage}[/]")

    # Get rid of multibyte charsets

    bad_words = ["UCS", "UTF", "CSUNICODE"]

    CHARSETS.remove("IBM1371")

    for x in CHARSETS[:]:
        if any(bad_word in x for bad_word in bad_words):
            CHARSETS.remove(x)
        elif len(convert("LATIN1", x, b"a")) != 1:
            # msg_warning(f"Removing {x}")
            CHARSETS.remove(x)

    # Cache base64-converting charsets

    for cfrom in CHARSETS:
        if convert(cfrom, "UCS4", BASE64_DIGITS):
            BASE64_CONVERTING_CHARSETS.append(cfrom)

    # Spicing things up
    # random.shuffle(CHARSETS)

    # Add state to the executor if it is not final
    def maybe_add(state: str) -> None:
        if len(state) > 1:
            futures[
                executor.submit(find_best_for, state.encode(), timeout, recave)
            ] = state
        else:
            msg_success(f"Found: {state!r}")

    def add_to_file(state: State) -> None:
        """Adds the chain to the storage file."""
        storage.append(
            f"""\
    {state.base.useful().decode()!r}: (
        {state.kept()!r},
        {state.nept()!r},
        {fc(state.conversions)!r}),
"""
        )

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {}
        maybe_add(base_state)

        try:
            while futures:
                for future in as_completed(futures):
                    state = future.result()
                    if state is None:
                        msg_failure(f"Unable to find a solution for {futures[future]}")
                    else:
                        maybe_add(state.kept())
                        maybe_add(state.nept())
                        add_to_file(state)
                    del futures[future]
                    display = ", ".join(to_str(list(futures.values()))[:3])
                    msg_success(f"Got {len(futures)} remaining: {display}...")
                    break
        except KeyboardInterrupt:
            STOP = True
            executor.shutdown(wait=False, cancel_futures=True)
            raise  # handled by ten


@dataclass(frozen=True)
class State:
    """A state is a set of data that we want to split in two. It contains the applied
    filters, the resulting state, and holds a reference to the base state.
    """

    base: State
    data: bytes
    size: int
    conversions: tuple[Conversion, ...]
    failures: int

    def useful(self) -> bytes:
        return self.data[: self.size]

    def kept(self) -> str:
        return bytes(
            (a for a, b in zip(self.base.useful(), self.useful()) if b in HEXDIGITS)
        ).decode()

    def nept(self) -> str:
        return bytes(
            (a for a, b in zip(self.base.useful(), self.useful()) if b not in HEXDIGITS)
        ).decode()

    def has_badchars(self) -> bool:
        return any(x in self.data for x in BLOCKING)

    def proximity(self) -> int:
        return abs(len(self.kept()) - len(self.nept()))


def has_decent_proximity(state: State) -> bool:
    """Is it close enough to a 50/50 split?"""
    nb = len(state.kept())
    match state.size:
        case 2:
            return nb == 1
        case 3:
            return 1 <= nb <= 2
        case _:
            return 0.4 <= nb / state.size <= 0.6


def maybe_remove_translit_ignore(
    cfrom: str, cto: str, current: State, new: State
) -> State:
    """Can we remove the TRANSLIT//IGNORE from the conversion, saving space?"""
    # TODO This does not work somehow: try with convert.iconv.IBM1390.SJIS for instance
    # Also, TRANSLIT is often (always?) enough
    if convert(cfrom, cto, current.data) != new.data:
        return new

    # Also check with a zero in between each char
    start = bytes(sum(((x, 0) for x in current.data), ()))
    expect = bytes(sum(((x, 0) for x in new.data), ()))

    if convert(cfrom, cto, start) != expect:
        # msg_warning("WAS RIGHT TO SKIP")
        return new
    return replace(new, conversions=new.conversions[:-1] + (fi(cfrom, cto),))


def is_new_best(new: State, best: State) -> bool:
    """Is `new` a better split than `best`?"""

    if best and new.proximity() > best.proximity():
        return False

    fc_new_conversions = fc(new.conversions)

    # Exact match? order by payload size
    if best and new.proximity() == best.proximity():
        if len(fc_new_conversions) >= len(fc(best.conversions)):
            return False

    kept = new.kept()
    nept = new.nept()

    part = len(kept) / new.size
    msg_info(f"{part:.02%} {new.base.useful()!r} {kept!r} {nept!r}")
    return True


def find_best_for(base_state: bytes, timeout: int, recave: int) -> State:
    """Finds the best split for a given base state."""
    global STOP

    msg_info(f"Processing {base_state}")
    size = len(base_state)

    base_state = base_state + BASE64_DIGITS + b"="

    # Misalign the state as it will get rid of remaining 2-byte/4-byte charsets
    if len(base_state) % 2 == 0:
        base_state += b"="

    # Setup first state
    base_state: State = State(None, base_state, size, (), 0)
    base_state = replace(base_state, base=base_state)
    states = [base_state]

    KNOWN_STATES = {base_state.data}
    watch = stopwatch()

    # Will hopefully store a nice split
    best: State = None

    while states:
        added = 0

        # Pick a state normally
        # current_state_base = states.pop()
        # Pick a state randomly
        current_state_base = states.pop(random.randrange(len(states)))

        # I refuse to rename this variable
        for with_cuicui in (-1, 0, 1, 2, 3):
            # Do we need to stop?

            if STOP:
                return best
            if best and watch.elapsed() > recave:
                msg_info("Timeout reached, exiting (2)")
                return best
            elif not best and watch.elapsed() > timeout:
                msg_info("Timeout reached, exiting (1)")
                return best

            # If cuicui is set, build a new state which consists of the Nth digit of the
            # base64 of the QPE of each byte. For instance, with 2, the byte "\x1F"
            # becomes =1F, whose B64 is PTFG. We thus store F. For a byte that is not
            # converted by QPE, such as A, it becomes A=0, and its B64 is QT0w, so we
            # store 0.

            if with_cuicui != -1:
                data = b"".join(
                    base64.encode(qpe(x))[with_cuicui].encode()
                    for x in niter(current_state_base.data, 1)
                )

                if data in KNOWN_STATES:
                    continue

                match with_cuicui:
                    case 0:
                        added_conversion = (QPE, B64E)
                    case 1:
                        added_conversion = (QPE, B64E, SWAP2)
                    case 2:
                        added_conversion = (QPE, B64E, SWAP2, SWAP4)
                    case 3:
                        added_conversion = (QPE, B64E, SWAP4)

                conversions = current_state_base.conversions + added_conversion

                if conversions[0] != "convert.iconv.L1.UTF16LE":
                    conversions = ("convert.iconv.L1.UTF16LE",) + conversions

                current = replace(
                    current_state_base,
                    data=data,
                    conversions=conversions,
                )

                # Maybe the state is useful already
                if has_decent_proximity(current) and is_new_best(current, best):
                    best = current
                    watch.start()
                    continue
            else:
                current = current_state_base

            # If the new state has a character that is present in more than 40% of the
            # cases, we can discard the state, as we won't reach a compromise
            if current.size > 2:
                useful = current.useful()
                _, nb = Counter(useful).most_common(1)[0]
                if nb > current.size * 0.6:
                    # msg_warning(f"Aborting this state, impossible!")
                    continue

            # Only convert from charsets that are actually able to convert
            if with_cuicui == -1:
                in_charsets = []
                for cfrom in CHARSETS:
                    if convert(cfrom, "UCS4", current.data):
                        in_charsets.append(cfrom)
            else:
                in_charsets = BASE64_CONVERTING_CHARSETS

            # Iterate over all possible conversions, trying to build a new state

            for cfrom, cto in product(in_charsets, CHARSETS):
                if STOP:
                    return best

                tx = f"{cto}//TRANSLIT//IGNORE"
                new = State(
                    base_state,
                    convert(cfrom, tx, current.data),
                    current.size,
                    current.conversions + (fi(cfrom, tx),),
                    current.failures + 1,
                )

                if len(new.data) != len(base_state.data):
                    continue

                if new.data in KNOWN_STATES:
                    continue

                new = maybe_remove_translit_ignore(cfrom, cto, current, new)

                if has_decent_proximity(new):
                    # Add final QPE if required, i.e. if there is R/N
                    if new.has_badchars():
                        new = replace(new, conversions=new.conversions + (QPE,))
                    if is_new_best(new, best):
                        best = new
                        watch.start()
                elif len(states) < 1000:
                    if new.failures > 1:
                        continue
                    KNOWN_STATES.add(new.data)
                    states.append(new)
                    added += 1
        # print(f"Added {added} states")

    return best


# Helper functions


def qpe(byte: bytes) -> bytes:
    """Converts a byte to its quoted-printable representation, assuming it is followed
    by a null byte.
    We're only interested in at most three chars, so chars that get converted are kept
    as-is (for instance, "@" becomes "=40"), but chars that are not converted are
    concatenated with "=0", which is part of the three bytes of the converted null byte
    that follows.
    """
    if byte in QPE_UNCONVERTED_BYTES:
        # return "???".encode()
        return byte + b"=0"
    return f"={byte[0]:02X}".encode()


def fc(x: list[str]) -> str:
    return "|".join(x)


def fi(x, y) -> str:
    return f"convert.iconv.{x}.{qs.encode(y)}"


main()
