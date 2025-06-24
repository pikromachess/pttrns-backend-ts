import {Api, HttpClient} from "@ton-api/client";
import * as dotenv from 'dotenv';

dotenv.config();

const httpClient = new HttpClient({
    baseUrl: process.env.TON_API_BASE_URL || 'https://testnet.tonapi.io',
    baseApiParams: {
        headers: {
            Authorization: `Bearer REDACTED`,
            'Content-type': 'application/json'
        }
    }
});

export const tonapi = new Api(httpClient);
