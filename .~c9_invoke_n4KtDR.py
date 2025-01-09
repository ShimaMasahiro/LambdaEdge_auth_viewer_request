# Program Name: auth_viewer_request
# Lambda@Edge
# aws lambda python 3.13
# Creation Date: 2024-12-20
# Last Modified Date: 2024-12-23
# CloudFront サイトにパスワードを入力してアクセスする

import base64
from datetime import datetime, timedelta
import logging

# ロガーの設定
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

def lambda_handler(event, context):

    # リクエストの取得
    request = event['Records'][0]['cf']['request']
    logger.debug(f'request: {request}')
    # ヘッダの取得
    headers = request['headers']
    logger.debug(f'headers: {headers}')

    # 日本時間の現在の日付
    JST = datetime.utcnow() + timedelta(hours=9)
    logger.debug(f'JST: {JST}')

    # 日付パスワード
    day_password = f'{JST.month:02d}{JST.day:02d}'
    logger.debug(f'day_password: {day_password}')

    # マスターパスワード# デフォルト値を1440に設定
    master_password = 'shima' 
    logger.debug(f"Master password: {master_password}")

    # 日付パスワードとマスターパスワード
    valid_passwords = [day_password, master_password]
    logger.debug(f'valid passwords: {valid_passwords}')

    # ヘッダからクッキーを取得
    cookies = headers.get('cookie', [])
    logger.debug(f'Cookies: {cookies}')
    
    for cookie in cookies:
        if 'auth=' in cookie['value']:
            # パスワード入力値
            saved_password = cookie['value'].split('auth=')[1].split(';')[0]
            logger.debug(f'saved_password: {saved_password}')
            # 入力値と設定値が同じ場合
            if saved_password in valid_passwords:
                logger.info('Password from cookie is valid.')
                return request

    # Authorizationヘッダを取得
    auth_header = headers.get('authorization', [])
    logger.debug(f'auth_header: {auth_header}')

    if auth_header:
        # Authorizationヘッダをデコード
        encoded_credentials = auth_header[0]['value'].split(' ')[1]
        logger.debug(f'encoded_credentials: {encoded_credentials}')

        try:
            credentials = base64.b64decode(encoded_credentials).decode('utf-8')
            password = credentials.split(':', 1)[1]
            logger.debug(f'password: {password}')
        except (IndexError, ValueError, base64.binascii.Error) as e:
            logger.error(f"Error decoding credentials: {e}")
            return {
                'status': '401',
                'statusDescription': 'Unauthorized',
                'headers': {
                'www-authenticate': [{
                'key': 'WWW-Authenticate',
                'value': 'Basic realm="Protected Content"'
                    }]
                }
            }

        # パスワードが正しい場合
        if password in valid_passwords:
            logger.info('Password from Authorization header is valid.')
            # Cookieを設定してリクエストを許可
            return {
                'status': '302',
                'statusDescription': 'Found',
                'headers': {
                    'set-cookie': [{
                        'key': 'Set-Cookie',
                        'value': f'auth={password}; Path=/; Max-Age=7200'  # 2時間有効
                    }],
                    'location': [{
                        'key': 'Location',
                        'value': request['uri']  # 元のリクエストURIに戻す
                    }]
                }
            }

    # 認証が必要な場合、401を返す
    logger.debug('Authorization failed. Returning 401.')
    return {
        'status': '401',
        'statusDescription': 'Unauthorized',
        'headers': {
            'www-authenticate': [{
                'key': 'WWW-Authenticate',
                'value': 'Basic realm="Protected Content"'
            }]
        }
    }
