import json
import os.path
import socket
import sys
import argparse
import logging
import boto3
import requests as requests

from typing import Any
from botocore.exceptions import ClientError
from netaddr import IPNetwork
from termcolor import colored

logging.basicConfig(format="%(process)d - %(levelname)s - %(message)s", level=logging.INFO)


def banner():
    print("""
 _______  ___      _______  _______  _______  ______    ___   _______    _______  _______  ___     
|       ||   |    |       ||       ||       ||    _ |  |   | |       |  |       ||       ||   |    
|    ___||   |    |    ___||       ||_     _||   | ||  |   | |       |  |    ___||    ___||   |    
|   |___ |   |    |   |___ |       |  |   |  |   |_||_ |   | |       |  |   |___ |   |___ |   |    
|    ___||   |___ |    ___||      _|  |   |  |    __  ||   | |      _|  |    ___||    ___||   |___ 
|   |___ |       ||   |___ |     |_   |   |  |   |  | ||   | |     |_   |   |___ |   |___ |       |
|_______||_______||_______||_______|  |___|  |___|  |_||___| |_______|  |_______||_______||_______|
    """)


def info(message: str) -> None:
    """
    Log information
    :param message: The message
    """
    logging.info(colored(message, "green"))


def warn(message: str) -> None:
    """
    Log a warning
    :param message: The message
    """
    logging.warning(colored(message, "yellow", attrs=["bold"]))


def detect(message: str) -> None:
    """
    Log a detection
    :param message: The message
    """
    logging.info(colored(message, "red", attrs=["bold"]))


def get_access_block(s3, bucket_name: str) -> Any:
    """
    Get the access block policies for the target bucket
    :param s3: The boto client
    :param bucket_name: The bucket name
    :return: The access block policies
    """
    return s3.get_public_access_block(Bucket=bucket_name)


def get_bucket_cors(s3, bucket_name: str) -> Any:
    """
    Get the CORS policies for the target bucket
    :param s3: The boto client
    :param bucket_name: The bucket name
    :return: The CORS policies
    """
    return s3.get_bucket_cors(Bucket=bucket_name)


def populate_access_block(block, bucket_collection: dict) -> None:
    """
    Populate the access block status and policies
    :param block: The block object return from the boto client
    :param bucket_collection: The bucket collection
    """
    if block:
        # If we have a block object, then set access_block to True
        bucket_collection["access_block"] = True
        access_block = {"block_public_acls": block['PublicAccessBlockConfiguration']['BlockPublicAcls'],
                        "block_public_policy": block['PublicAccessBlockConfiguration']['BlockPublicPolicy']
                        }
        bucket_collection["access_block_policies"] = access_block
    else:
        # If the block object is None then set the access_block to False
        bucket_collection["access_block"] = False


def get_s3_bucket_policy(s3, bucket_name: str) -> str:
    """
    Get and return the policy for the S3 bucket
    :param s3: The s3 client object
    :param bucket_name: The bucket name
    :return: The policy
    """
    result = s3.get_bucket_policy(Bucket=bucket_name)
    return result["Policy"]


def get_s3_bucket_exposure(bucket_collections: list) -> None:
    """
    Determine the exposure of all the S3 buckets that can be discovered in the environment.
    """
    s3 = boto3.client("s3")
    for bucket in s3.list_buckets()["Buckets"]:
        bucket_collection = {}
        info(f"[+] Querying {bucket['Name']} ...")
        try:
            bucket_collection["bucket_name"] = bucket["Name"]
            result = get_s3_bucket_policy(s3, bucket["Name"])
            if result:
                bucket_policies = list()
                statements = json.loads(result)["Statement"]
                if len(statements) > 0:
                    detect(f"[+] Found {len(statements)} bucket policies")
                    for s in statements:
                        bucket_policies.append(s)
                bucket_collection["bucket_policies"] = bucket_policies
            response: dict = get_bucket_cors(s3, bucket["Name"])
            rules: list = response["CORSRules"]
            bucket_collection["cors_rules"] = list()
            if len(rules) > 0:
                # If we have a list of rules set cors_policy to True
                bucket_collection["cors_policy"] = True
                detect(f"[+] Found CORS rules {len(rules)}")
                for rule in rules:
                    bucket_collection["cors_rules"].append(rule)
            else:
                # if we don't have any rules set cors_policy to False
                bucket_collection["cors_policy"] = False
            block = get_access_block(s3, bucket["Name"])
            populate_access_block(block, bucket_collection)
        except ClientError:
            bucket_collection["cors_policy"] = False
            try:
                block = get_access_block(s3, bucket["Name"])
                populate_access_block(block, bucket_collection)
            except ClientError:
                bucket_collection["access_block"] = False
            bucket_collections.append(bucket_collection)


def get_route53_domains() -> list:
    """
    Get a list of all the Route53 domains
    :return: The list of domains
    """
    domains = list()
    route53 = boto3.client('route53')
    zones: dict = route53.list_hosted_zones()
    # get last record name only
    for zone in zones['HostedZones']:
        zone_id = zone['Id']
        next_record_name: str = route53.list_resource_record_sets(HostedZoneId=zone_id)['ResourceRecordSets'][0]['Name']
        while True:
            zone_records: dict = route53.list_resource_record_sets(HostedZoneId=zone_id,
                                                                   StartRecordName=next_record_name)
            for record in zone_records['ResourceRecordSets']:
                if record['Type'] == 'CNAME':
                    domain_name = record['Name'][:-1]
                    detect(f"[+] Found domain {domain_name}")
                    domains.append(domain_name)
            if 'NextRecordName' in zone_records:
                next_record_name = zone_records['NextRecordName']
            else:
                break
    return domains


def get_cloudfront_ranges() -> list:
    """
    Get all CloudFront ranges
    :return: The ranges
    """
    ranges = list()
    url = "https://ip-ranges.amazonaws.com/ip-ranges.json"
    response = requests.get(url)
    data: dict = response.json()
    for prefix in data["prefixes"]:
        service: str = prefix.get("service")
        if service == "CLOUDFRONT":
            detect(f"[+] Found CloudFront service {service} = {prefix.get('ip_prefix')}")
            ranges.append(prefix.get("ip_prefix"))
    return ranges


def find_cloudfront_domain(target: str, cloudfront_ranges: list) -> bool:
    """
    Find CloudFront domains in the list of CloudFront IP ranges
    :param target: The target domains
    :param cloudfront_ranges: The CloudFront IP ranges
    """
    if target.endswith("cloudfront.net"):
        return False
    ips = list()
    try:
        ips = socket.gethostbyname_ex(target)[2]
        # If this fails, it's all good, just continue on
    except Exception:
        pass
    for ip in ips:
        for ip_range in cloudfront_ranges:
            network = IPNetwork(ip_range)
            if ip in network:
                detect(f"[+] Found CloudFront domain {target}")
                return True


def analyze_cloudfront_domains(domains: list) -> list:
    """
    Analyze the CloudFront domains for misconfigurations
    :param domains: The domains
    """
    potentially_misconfigured_domains = list()
    for domain in domains:
        try:
            response = requests.get("".join(["http://", domain]))
            info(f"[+] Analyzing {domain} for misconfigurations ... [{response.status_code}]")
            if response.status_code == 403:
                potentially_misconfigured_domains.append(domain)
        except requests.RequestException:
            # TODO ~ Handle this when it comes up
            pass
    return potentially_misconfigured_domains


def get_domains_from_input(input_file: str) -> list:
    """
    Retrieve a list of domains from an input file
    :param input_file: The input file
    :return: The list of domains
    """
    domains = list()
    if os.path.isfile(input_file):
        try:
            with open(input_file, "r") as fp:
                for line in fp.readlines():
                    domains.append(line.strip())
        except IOError as io_error:
            raise io_error
    else:
        raise IOError(f"{input_file} is not a file!")
    return domains


def get_cloudfront_misconfigurations(input_file=None) -> list:
    """
    Return CloudFront misconfigurations
    :return: The misconfigurations
    """
    if input_file:
        domains: list = get_domains_from_input(input_file)
    else:
        domains: list = get_route53_domains()
    cloudfront_domains = list()
    cloudfront_ranges = get_cloudfront_ranges()
    for d in domains:
        result = find_cloudfront_domain(d, cloudfront_ranges)
        if result:
            cloudfront_domains.append(d)
    # Begin mis-configuration analysis
    return analyze_cloudfront_domains(cloudfront_domains)


def save_collection_to_disk(file_name: str, collection: Any) -> None:
    """
    Save a collection to disk
    :param file_name: The output file name
    :param collection: The collection
    """
    try:
        with open(file_name, "w") as fp:
            fp.write(json.dumps(collection, indent=2))
    except IOError as io_error:
        raise io_error


def get_security_group_detections(instances: list) -> list:
    """
    Get the security groups for a list of EC2 instances
    :param instances: The EC2 instances
    :return: The security groups
    """
    security_groups = list()
    for instance in instances:
        detect(f"[+] Found InstanceId {instance['InstanceId']}")
        if len(instance["SecurityGroups"]) > 0:
            for group in instance["SecurityGroups"]:
                detection = {"instance_id": instance["InstanceId"], "security_groups": group}
                security_groups.append(detection)
    return security_groups


def get_ec2_external_cidr() -> list:
    """
    Get all external EC2 resources with an 0.0.0.0/0 CIDR block
    :return: A list of external EC2 resources
    """
    ec2 = boto3.client('ec2')
    response = ec2.describe_instances()
    reservations = response["Reservations"]
    info(f"[+] Found {len(reservations)} Reservations")
    detections_with_ranges = list()
    for r in reservations:
        instances = r["Instances"]
        detections = get_security_group_detections(instances)
        for detection in detections:
            detection["ip_permissions"] = list()
            group_identifier = detection["security_groups"]["GroupId"]
            info(f"[+] Starting search for {group_identifier}")
            details = ec2.describe_security_groups(GroupIds=[group_identifier])
            security_groups = details["SecurityGroups"]
            ip_permissions = {"ranges": list()}
            for group in security_groups:
                for permission in group["IpPermissions"]:
                    if len(permission["IpRanges"]) > 0:
                        for ip_range in permission["IpRanges"]:
                            if ip_range["CidrIp"] == "0.0.0.0/0":
                                detect(f"[+] Found 0.0.0.0/0 range for port {permission['FromPort']} "
                                       f"=> port {permission['ToPort']}")
                                ip_permissions["from_port"] = permission["FromPort"]
                                ip_permissions["to_port"] = permission["ToPort"]
                                ip_permissions["ranges"].append(ip_range)
            if len(ip_permissions["ranges"]) > 0:
                detection["ip_permissions"].append(ip_permissions)
                detections_with_ranges.append(detection)
    return detections_with_ranges


def get_ec2_public_addresses() -> list:
    """
    Get a list of public IP addresses for all ec2 instances.
    :return: The list of IP addresses
    """
    public_ip_addresses = list()
    ec2 = boto3.client('ec2')
    response = ec2.describe_instances()
    reservations = response["Reservations"]
    for r in reservations:
        instances = r["Instances"]
        for instance in instances:
            if "PublicIpAddress" in instance:
                public_ip_addresses.append(instance["PublicIpAddress"])
    return list(set(public_ip_addresses))


def save_list_to_disk(file_name: str, data: list) -> None:
    try:
        with open(file_name, "w") as fp:
            for item in data:
                fp.write(item)
                fp.write("\n")
    except IOError as io_error:
        raise io_error


PARSER = argparse.ArgumentParser()
PARSER.add_argument("--s3-buckets", action="store_true")
PARSER.add_argument("--cloudfront", action="store_true")
PARSER.add_argument("--external-ec2-resources", action="store_true")
PARSER.add_argument("--ec2-public-ip-addresses", action="store_true")
PARSER.add_argument("--output")
PARSER.add_argument("--input-file")

if __name__ == "__main__":
    banner()
    try:
        args = PARSER.parse_args()
        if args.s3_buckets:
            exposure_bucket_collections = list()
            get_s3_bucket_exposure(exposure_bucket_collections)
            if args.output:
                # Save the s3 output
                save_collection_to_disk(args.output, exposure_bucket_collections)
        if args.cloudfront:
            misconfigured_domains: list = get_cloudfront_misconfigurations(args.input_file)
            for item in misconfigured_domains:
                warn(f"[!] Potentially misconfigured domain {item}")
        if args.external_ec2_resources:
            external_resources = get_ec2_external_cidr()
            # TODO ~ Turn into a function
            # Save external ec2 resources
            if args.output:
                save_collection_to_disk(args.output, external_resources)
        if args.ec2_public_ip_addresses:
            addresses = get_ec2_public_addresses()
            for i in addresses:
                detect(f"[+] {i}")
            # Save public IP addresses
            if args.output:
                save_list_to_disk(args.output, addresses)
    except KeyboardInterrupt:
        sys.exit(0)
