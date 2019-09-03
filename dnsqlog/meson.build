# C module: dnsqlog

dnsqlog_src = files([
  'crc64.c',
  'log.c',
  'program.c',
  'dnsqlog.c',
])
c_src_lint += dnsqlog_src

dnsqlog_mod = shared_module(
  'dnsqlog',
  dnsqlog_src,
  include_directories: mod_inc_dir,
  name_prefix: '',
  install: true,
  install_dir: modules_dir,
)
