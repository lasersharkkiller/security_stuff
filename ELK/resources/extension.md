# Zeek Script for Custom Extensions

Add the `extension.zeek` script and add the following code:

```vim
type Extension: record {
   ## The log stream that this log was written to.
   stream:   string &log;
   ## The name of the system that wrote this log. This
   ## is defined in the  const so that
   ## a system running lots of processes can give the
   ## same value for any process that writes a log.
   system:   string &log;
   ## The name of the process that wrote the log. In
   ## clusters, this will typically be the name of the
   ## worker that wrote the log.
   proc:     string &log;
};

function add_log_extension(path: string): Extension
{
   return Extension($stream = path,
                    $system = "sensor1",
                    $proc   = peer_description);
}

redef Log::default_ext_func   = add_log_extension;
redef Log::default_ext_prefix = "@";
redef Log::default_scope_sep  = "_";
```
