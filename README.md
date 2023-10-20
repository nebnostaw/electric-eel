# electric-eel (WIP)
AWS Toolkit Python Script

```
 _______  ___      _______  _______  _______  ______    ___   _______    _______  _______  ___     
|       ||   |    |       ||       ||       ||    _ |  |   | |       |  |       ||       ||   |    
|    ___||   |    |    ___||       ||_     _||   | ||  |   | |       |  |    ___||    ___||   |    
|   |___ |   |    |   |___ |       |  |   |  |   |_||_ |   | |       |  |   |___ |   |___ |   |    
|    ___||   |___ |    ___||      _|  |   |  |    __  ||   | |      _|  |    ___||    ___||   |___ 
|   |___ |       ||   |___ |     |_   |   |  |   |  | ||   | |     |_   |   |___ |   |___ |       |
|_______||_______||_______||_______|  |___|  |___|  |_||___| |_______|  |_______||_______||_______|
```

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
### S3 Bucket Access Control
Determine if the S3 buckets in your AWS environment have public access.
```
python3 electric-eel.py --s3-buckets
```
Save the results to a file.
```
python3 electric-eel.py --s3-buckets --output results.json
```
