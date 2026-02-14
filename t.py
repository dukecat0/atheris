import sys
import atheris
import argcomplete


def TestOneInput(data):
  fdp = atheris.FuzzedDataProvider(data)
  try:
    argcomplete.split_line(fdp.ConsumeUnicodeNoSurrogates(sys.maxsize))
  except (argcomplete.ArgcompleteException):
    pass


def main():
  atheris.instrument_all()
  atheris.Setup(sys.argv, TestOneInput)
  atheris.Fuzz()


if __name__ == "__main__":
  main()