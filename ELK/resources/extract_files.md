# Zeek File Extraction Script

Create the `extract_files.zeek` script.

```vim
@load /usr/share/zeek/policy/frameworks/files/extract-all-files.zeek
redef FileExtract::prefix = "/data/zeek/extracted_files/";
redef FileExtract::default_limit = 104857600;
```
