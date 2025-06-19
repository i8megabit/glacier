import boto3
import botocore
import certifi
from botocore.config import Config

# Обработка проблем с configparser на разных системах
try:
    import configparser
except ImportError:
    try:
        # Для Python 2 / старых систем
        import ConfigParser as configparser
    except ImportError:
        print("⚠️ S3: configparser недоступен, устанавливается fallback")
        configparser = None


def get_client_s3(url_s3, region, user, access_key, py_version, is_cert=True):
    try:
        if is_cert:
            certificate = certifi.where()
        else:
            certificate = "./cert/s3-msk2.crt"

        if py_version['major'] == 3 and py_version['minor'] >= 8:
            config_s3 = Config(
                request_checksum_calculation="when_required",
                response_checksum_validation="when_required")
        else:
            config_s3 = None

        session = boto3.session.Session()
        s3 = session.client(
            service_name='s3',
            region_name=region,
            endpoint_url=url_s3,
            verify=certificate,
            aws_access_key_id=user,
            aws_secret_access_key=access_key,
            config=config_s3
        )

        return s3
        
    except Exception as e:
        print(f"❌ S3: Client creation failed: {e}")
        return None

def upload_file_s3(s3, bucket, file_path, file_in_s3):
    success = True
    try:
        s3.upload_file(file_path, bucket, file_in_s3)
    except boto3.exceptions.S3UploadFailedError as err:
        print(f"S3: error upload file: {err}")
        success = False
    except (botocore.exceptions.EndpointConnectionError, botocore.exceptions.ReadTimeoutError) as err:
        print(f"S3: unavailable: {err}")
        success = False

    return success

def read_from_s3(s3, bucket):
    contents = []
    list_obj = s3.list_objects(Bucket=bucket)
    if 'Contents' in list_obj:
        contents = list_obj['Contents']
    else:
        print("S3: bucket is empty")

    return contents

def get_object(s3, bucket, obj_key):
    with open("test.file", 'wb') as f:
        s3.download_fileobj(bucket, obj_key, f)
        print(f"S3: download file {obj_key}")
