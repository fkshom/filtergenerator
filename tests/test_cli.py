import pytest
from assertpy import assert_that, fail
import yaml
import logging
import filtergenerator.cli as cli
import io
import textwrap
import tempfile
import subprocess
import os
import sys
from pprint import pprint as pp

class Test_gen():
    def test_stdoutに出力される(self, capfd):
        definitionfile = "sample.yaml"
        args = ['genrouter', definitionfile]
        cli.main(args=args)
        out, err = capfd.readouterr()
        assert_that(out.rstrip()).is_equal_to("")
