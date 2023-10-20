# electric-eel (WIP)
AWS Toolkit Python Script
## Usage
First you will need to configure your AWS credentials.

[https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html)

### Check for CloudFront Misconfigurations
```
python3 electric-eel.py --cloud-front
```
This will attempt to pull DNS records directly from Route53 in your AWS environment.
You can also supply a list of domains, which will bypass the Route53 lookup.
```
python3 electric-eel.py --cloud-front --input-file domains.txt
```
