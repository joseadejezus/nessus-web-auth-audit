"""nwaa: Nessus-driven web authentication surface auditor.

Parses a .nessus scan, identifies web login pages within the scanned
scope, fingerprints the device behind each one, screenshots them, and
(optionally) tests credentials against them — either operator-supplied,
or the published vendor defaults for the detected device. Built for Kali
Linux. See docs/SECURITY.md before using this tool against anything you
are not explicitly authorized to test.
"""

__version__ = "0.2.0"
