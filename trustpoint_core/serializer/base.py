"""The base module provides abstract base Serializer classes."""

from __future__ import annotations

import abc


class Serializer(abc.ABC):
    """Abstract Base Class for all Serializer classes.

    Warnings:
        Serializer classes do not include any type of validation.
        They are merely converting between formats.
    """

    @abc.abstractmethod
    def serialize(self) -> bytes:
        """The default serialization method."""
