'''
The native code disassembler for trueseeing.
'''

from __future__ import annotations
from typing import TYPE_CHECKING
import os
import sys
from pathlib import Path
from subprocess import CalledProcessError
from tempfile import TemporaryDirectory

if TYPE_CHECKING:
  from typing import NoReturn, Protocol, Iterator, Set, Optional

  class TargetProfile(Protocol):
    def get_tag(self) -> str: ...
    def glob(self, path: Path) -> Iterator[Path]: ...
    def get_prescript(self) -> str: ...
    def get_postscript(self, path: Path) -> str: ...

__version__ = '1.0.0'

def get_cache_dir() -> Path:
  return Path('/cache')

def get_ghidra_path() -> Path:
  return Path('/app/ghidra')

def get_headless_analyzer() -> Path:
  return get_ghidra_path()/'support'/'analyzeHeadless'

def get_cpu_count() -> int:
  return len(os.sched_getaffinity(0))


class Config:
  def __init__(self) -> None:
    self.debug = False


config = Config()


class UI:
  def fatal(self, s: str) -> NoReturn:
    self.stderr('[-] fatal: {s}'.format(s=s))
    sys.exit(2)

  def failure(self, s: str) -> None:
    self.stderr('[-] {s}'.format(s=s))

  def success(self, s: str) -> None:
    self.stderr('[+] {s}'.format(s=s))

  def debug(self, s: str) -> None:
    if config.debug:
      self.stderr('[.] {s}'.format(s=s))

  def warn(self, s: str) -> None:
    self.info(s)

  def info(self, s: str) -> None:
    self.stderr('[*] {s}'.format(s=s))

  def stderr(self, s: str) -> None:
    sys.stderr.write(f'{s}\n')


ui = UI()


class Disassembler:
  def __init__(self, profile: TargetProfile) -> None:
    self._profile = profile
    self._wd = get_cache_dir() / profile.get_tag()

  def _get_muter(self) -> str:
    return '' if config.debug else ' >/dev/null 2>&1'

  def _prep(self) -> None:
    if not self._wd.exists():
      self._wd.mkdir(parents=True)

  def extract(self, target: Path, overlay: bool = False, *, cmdline: Optional[str] = None) -> None:
    self._prep()
    d = self._get_binpath()
    if d.exists() and not overlay:
      from shutil import rmtree
      rmtree(str(d))
    from shlex import quote
    if cmdline is None:
      cmdline = '(mkdir -p {d} && cd {d} && unzip -o {fn}){q}'
    self._invoke(cmdline.format(d=d, fn=quote(str(target)), q=self._get_muter()))

  def _get_binpath(self) -> Path:
    return self._wd / 't'

  def analyze(self) -> None:
    self._prep()
    name = 'app' # XXX
    with TemporaryDirectory() as td:
      opts = Path(td) / 'opts.py'
      opts.write_text(self._profile.get_prescript())
      d = self._get_binpath()
      targets = list(self._profile.glob(d))
      for n, f in enumerate(targets):
        rf = f.relative_to(d)
        ui.info('analyzing ({n}/{t}): {path}'.format(n=n+1, t=len(targets), path=rf))
        pp = Path(name) / rf.parent
        self._invoke('(cd {d} && {analyze_headless} {wd} {pp} -max-cpu {cpus} -prescript {scriptfn} -import {rf}){q}'.format(d=self._get_binpath(), analyze_headless=get_headless_analyzer(), wd=self._wd, pp=pp, scriptfn=opts, cpus=self._get_optimal_parallelism(), rf=rf, q=self._get_muter()))

  def generate(self) -> None:
    import tarfile
    self._prep()
    name = 'app' # XXX
    outdir = Path('.')
    outfn = outdir / 'disasm.tar.gz'
    with TemporaryDirectory() as td:
      tmpfn = Path(td) / 'out.S'
      opts = Path(td) / 'opts.py'
      opts.write_text(self._profile.get_postscript(tmpfn))
      d = self._get_binpath()
      targets = list(self._profile.glob(d))
      with tarfile.open(outfn, 'w:gz', compresslevel=6) as tf:
        for n, f in enumerate(targets):
          rf = f.relative_to(d)
          ui.info('generating ({n}/{t}): {path}'.format(n=n+1, t=len(targets), path=rf))
          pp = Path(name) / rf.parent
          try:
            self._invoke('(cd {d} && {analyze_headless} {wd} {pp} -max-cpu {cpus} -postscript {scriptfn} -process {fn} -noanalysis){q}'.format(d=self._get_binpath(), analyze_headless=get_headless_analyzer(), wd=self._wd, pp=pp, scriptfn=opts, cpus=self._get_optimal_parallelism(), fn=f.name, q=self._get_muter()))
            with open(tmpfn, 'rb') as g:
              tf.addfile(tf.gettarinfo(name=tmpfn, arcname=f'{rf}.S'), fileobj=g)
            tmpfn.unlink()
          except CalledProcessError:
            ui.warn('generate failed, ignoring')

  def _invoke(self, cmd: str) -> None:
    from subprocess import run
    run(cmd, shell=True, check=True)

  def _get_optimal_parallelism(self) -> int:
    return min(10, get_cpu_count())

class APKDisassembler:
  def __init__(self, target: Path, skip_extract: bool = False, skip_analyze: bool = False, skip_generate: bool = False) -> None:
    self._d = Disassembler(self)
    self._target = target.resolve()
    self._skip_extract = skip_extract
    self._skip_analyze = skip_analyze
    self._skip_generate = skip_generate

  def do(self) -> None:
    try:
      if not self._skip_extract:
        self._d.extract(self._target)
      if not self._skip_analyze:
        self._d.analyze()
      if not self._skip_generate:
        self._d.generate()
    except CalledProcessError as e:
      ui.fatal('command failed ({code}): {cmd}'.format(cmd=e.cmd, code=e.returncode))

  def get_tag(self) -> str:
    return 'android'

  def glob(self, path: Path) -> Iterator[Path]:
    return path.glob('**/*.so')

  @classmethod
  def get_prescript(cls) -> str:
    return (
      'from ghidra.app.script import GhidraScript\n'
      'setAnalysisOption(currentProgram, "ELF Scalar Operand References", "true")\n'
    )

  @classmethod
  def get_postscript(cls, path: Path) -> str:
    return (
      'from java.io import File\n'
      'from ghidra.app.util.exporter import AsciiExporter\n'
      '\n'
      'e = AsciiExporter()\n'
      'opts = e.getOptions(None)\n'
      'for o in opts:\n'
      '  if o.getName() == " Address ":\n'
      '    o.setValue(20)\n'
      '  if o.getName() == " Operand ":\n'
      '    o.setValue(256)\n'
      '  if o.getName() == " End of Line ":\n'
      '    o.setValue(256)\n'
      '  if o.getName() == " Undefined Data ":\n'
      '    o.setValue(False)\n'
      'e.setOptions(opts)\n'
      'e.export(File("{path}"), currentProgram, None, monitor)\n'
    ).format(path=path)

class XAPKDisassembler(APKDisassembler):
  def __init__(self, target: Path, skip_extract: bool = False, skip_analyze: bool = False, skip_generate: bool = False) -> None:
    super().__init__(target, skip_extract=skip_extract, skip_analyze=skip_analyze, skip_generate=skip_generate)

  def do(self) -> None:
    try:
      if not self._skip_extract:
        self._extract()
      if not self._skip_analyze:
        self._d.analyze()
      if not self._skip_generate:
        self._d.generate()
    except CalledProcessError as e:
      ui.fatal('command failed ({code}): {cmd}'.format(cmd=e.cmd, code=e.returncode))

  def _extract(self) -> None:
    from zipfile import ZipFile
    with ZipFile(self._target) as zf:
      slices: Set[Path] = set()
      for namestr in zf.namelist():
        name = Path(namestr)
        if name.suffix.lower() != '.apk':
          continue
        ui.info(f'selecting slice: {namestr}')
        with TemporaryDirectory() as td:
          slice = Path(td) / 'slice.apk'
          slice.write_bytes(zf.read(namestr))
          self._d.extract(slice, overlay=bool(slices))
          slices.add(slice)

class IPADisassembler:
  def __init__(self, target: Path, skip_extract: bool = False, skip_analyze: bool = False, skip_generate: bool = False, dont_mangle: bool = False) -> None:
    self._d = Disassembler(self)
    self._target = target.resolve()
    self._skip_extract = skip_extract
    self._skip_analyze = skip_analyze
    self._skip_generate = skip_generate
    self._dont_mangle = dont_mangle

  def do(self) -> None:
    try:
      if not self._skip_extract:
        if self._dont_mangle:
          self._d.extract(self._target)
        else:
          self._d.extract(self._target, cmdline=r'(mkdir -p {d} && cd {d} && unzip -o {fn} && (bundle=$(echo Payload/*.app | sed -Ee "s/Payload\/|\.app$//g"); mv Payload/"$bundle".app/"$bundle" Payload/"$bundle".app/target && mv Payload/"$bundle".app Payload/target.app)){q}')
      if not self._skip_analyze:
        self._d.analyze()
      if not self._skip_generate:
        self._d.generate()
    except CalledProcessError as e:
      ui.fatal('command failed ({code}): {cmd}'.format(cmd=e.cmd, code=e.returncode))

  def get_tag(self) -> str:
    return 'ios'

  def glob(self, path: Path) -> Iterator[Path]:
    app = list(path.glob('Payload/*.app'))[0]
    for p in app.glob('**/Frameworks/*'):
      target = (p / (p.name.replace('.framework', '')))
      if target.exists():
        yield target
    target = (app / app.name.replace('.app', ''))
    if target.exists():
      yield target

  @classmethod
  def get_prescript(cls) -> str:
    return (
      'from ghidra.app.script import GhidraScript\n'
      'setAnalysisOption(currentProgram, "Condense Filler Bytes (Prototype)", "true")\n'
      'setAnalysisOption(currentProgram, "Scalar Operand References", "true")\n'
    )

  @classmethod
  def get_postscript(cls, path: Path) -> str:
    return APKDisassembler.get_postscript(path)

def entry0() -> None:
  from argparse import ArgumentParser
  parser = ArgumentParser()
  parser.add_argument('target', nargs=1)
  parser.add_argument('--debug', action='store_true')
  parser.add_argument('--no-extract', action='store_true')
  parser.add_argument('--no-analyze', action='store_true')
  parser.add_argument('--no-generate', action='store_true')
  parser.add_argument('--no-mangle', action='store_true')
  args = parser.parse_args()

  config.debug = args.debug

  target = Path(args.target[0])
  suf = target.suffix.lower()
  if suf == '.apk':
    APKDisassembler(target, skip_extract=args.no_extract, skip_analyze=args.no_analyze, skip_generate=args.no_generate).do()
  elif suf == '.ipa':
    IPADisassembler(target, skip_extract=args.no_extract, skip_analyze=args.no_analyze, skip_generate=args.no_generate, dont_mangle=args.no_mangle).do()
  elif suf == '.xapk':
    XAPKDisassembler(target, skip_extract=args.no_extract, skip_analyze=args.no_analyze, skip_generate=args.no_generate).do()
  else:
    ui.fatal('unknown format: {}'.format(suf[1:]))
