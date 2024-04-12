def combine_dicts(*dicts):
    combined_dict = {}
    for d in dicts:
        combined_dict.update(d)
    return combined_dict

dicts = [
    {
        'e926f4a430b18c98eed9a6a5208f1cf6': ('com.joeykrim.rootcheck', '/data/app/com.joeykrim.rootcheck-DFH-NOakigWc2YlFs7hwWA==/base.apk'),
        'f48b649cff4ed0d70439acb6dd5132a7': ('com.metasploit.stage', '/data/app/com.metasploit.stage-LI5GvVgvVNcEgPtLK5otjg==/base.apk')
    },
    {
        'f8fe23cdab84a446affadc835288d3f9': ('com.joeykrim.rootcheck', '/data/app/com.joeykrim.rootcheck-sDV4WgNrVwZJyejJvhdMuQ==/base.apk')
    },
    {
        'a_unique_key': ('com.example.app', '/data/app/com.example.app/base.apk')
    }
]

combined = {}
for d in dicts:
    combined.update(d)

print(combined)
