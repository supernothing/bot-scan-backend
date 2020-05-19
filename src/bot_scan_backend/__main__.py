from concurrent.futures import ThreadPoolExecutor
import socket

import click
import requests

from bot_events.events import ScanRequest, Result
from bot_events.producer import EventProducer
from bot_events.consumer import EventConsumer
from bot_events.db import get_walrus_db

from polyswarm_api.api import PolyswarmAPI
from polyswarm_api.types import resources

from .logging import get_logger

logger = get_logger()


class ResultWaiter(object):
    def __init__(self, api, producer):
        self.producer = producer
        self.api = api

    def wait_for_result(self, instance_id, context):
        try:
            result = self.api.wait_for_result(instance_id)
            event = Result()
            event.url = result.permalink
            event.polyscore = result.polyscore
            # TODO this emulates current bot, we can do better
            # I just need more reasonable thresholds for polyscore
            event.malicious = len(result.malicious_assertions) > 1
            event.context.CopyFrom(context)
            self.producer.add_event(event)
        except Exception as e:
            logger.exception('Exception occurred while waiting for result: %s %s %s', instance_id, context, e)



@click.command()
@click.option('--community', '-c', multiple=True, type=click.STRING, default='rho', envvar='POLYBOT_COMMUNITY')
@click.option('--redis', '-h', type=click.STRING, envvar='POLYBOT_REDIS', default='127.0.0.1',
              help='redis hostname')
@click.option('--consumer-name', type=click.STRING, envvar='POLYBOT_CONSUMER_NAME', default=socket.gethostname(),
              help='consumer name')
@click.option('--api-key', type=click.STRING, envvar='POLYBOT_API_KEY', default='',
              help='api key')
def bot_scan_backend(community, redis, consumer_name, api_key):
    session = requests.Session()
    api = PolyswarmAPI(api_key, community=community)
    consumer = EventConsumer(['scan-requests'], 'bot-scan-backend', consumer_name, get_walrus_db(redis), ScanRequest)
    producer = EventProducer('scan-results', get_walrus_db(redis))

    waiter = ResultWaiter(api, producer)

    with ThreadPoolExecutor() as pool:
        for event in consumer.iter_events():
            try:
                event = ScanRequest()
                if event.artifact_type == 'FILE':
                    stream = session.get(event.uri, stream=True).raw
                    result = api.submit(stream)
                elif event.artifact_type == 'URL':
                    result = api.submit(event.uri, artifact_type=resources.ArtifactType.URL)
                else:
                    logger.warning('Unsupported artifact type %s, maybe update this backend', event.artifact_type)
                    continue
                future = pool.submit(waiter.wait_for_result, result.id, event.context)

            except Exception as e:
                logger.exception('Exception occurred processing event %s: %s', event, e)
