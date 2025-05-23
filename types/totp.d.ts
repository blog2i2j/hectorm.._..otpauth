/**
 * TOTP: Time-Based One-Time Password Algorithm.
 * @see [RFC 6238](https://datatracker.ietf.org/doc/html/rfc6238)
 */
export class TOTP {
    /**
     * Default configuration.
     * @type {{
     *   issuer: string,
     *   label: string,
     *   issuerInLabel: boolean,
     *   algorithm: string,
     *   digits: number,
     *   period: number
     *   window: number
     * }}
     */
    static get defaults(): {
        issuer: string;
        label: string;
        issuerInLabel: boolean;
        algorithm: string;
        digits: number;
        period: number;
        window: number;
    };
    /**
     * Calculates the counter. i.e. the number of periods since timestamp 0.
     * @param {Object} [config] Configuration options.
     * @param {number} [config.period=30] Token time-step duration.
     * @param {number} [config.timestamp=Date.now] Timestamp value in milliseconds.
     * @returns {number} Counter.
     */
    static counter({ period, timestamp }?: {
        period?: number | undefined;
        timestamp?: number | undefined;
    }): number;
    /**
     * Calculates the remaining time in milliseconds until the next token is generated.
     * @param {Object} [config] Configuration options.
     * @param {number} [config.period=30] Token time-step duration.
     * @param {number} [config.timestamp=Date.now] Timestamp value in milliseconds.
     * @returns {number} counter.
     */
    static remaining({ period, timestamp }?: {
        period?: number | undefined;
        timestamp?: number | undefined;
    }): number;
    /**
     * Generates a TOTP token.
     * @param {Object} config Configuration options.
     * @param {Secret} config.secret Secret key.
     * @param {string} [config.algorithm='SHA1'] HMAC hashing algorithm.
     * @param {number} [config.digits=6] Token length.
     * @param {number} [config.period=30] Token time-step duration.
     * @param {number} [config.timestamp=Date.now] Timestamp value in milliseconds.
     * @returns {string} Token.
     */
    static generate({ secret, algorithm, digits, period, timestamp }: {
        secret: Secret;
        algorithm?: string | undefined;
        digits?: number | undefined;
        period?: number | undefined;
        timestamp?: number | undefined;
    }): string;
    /**
     * Validates a TOTP token.
     * @param {Object} config Configuration options.
     * @param {string} config.token Token value.
     * @param {Secret} config.secret Secret key.
     * @param {string} [config.algorithm='SHA1'] HMAC hashing algorithm.
     * @param {number} [config.digits=6] Token length.
     * @param {number} [config.period=30] Token time-step duration.
     * @param {number} [config.timestamp=Date.now] Timestamp value in milliseconds.
     * @param {number} [config.window=1] Window of counter values to test.
     * @returns {number|null} Token delta or null if it is not found in the search window, in which case it should be considered invalid.
     */
    static validate({ token, secret, algorithm, digits, period, timestamp, window }: {
        token: string;
        secret: Secret;
        algorithm?: string | undefined;
        digits?: number | undefined;
        period?: number | undefined;
        timestamp?: number | undefined;
        window?: number | undefined;
    }): number | null;
    /**
     * Creates a TOTP object.
     * @param {Object} [config] Configuration options.
     * @param {string} [config.issuer=''] Account provider.
     * @param {string} [config.label='OTPAuth'] Account label.
     * @param {boolean} [config.issuerInLabel=true] Include issuer prefix in label.
     * @param {Secret|string} [config.secret=Secret] Secret key.
     * @param {string} [config.algorithm='SHA1'] HMAC hashing algorithm.
     * @param {number} [config.digits=6] Token length.
     * @param {number} [config.period=30] Token time-step duration.
     */
    constructor({ issuer, label, issuerInLabel, secret, algorithm, digits, period, }?: {
        issuer?: string | undefined;
        label?: string | undefined;
        issuerInLabel?: boolean | undefined;
        secret?: string | Secret | undefined;
        algorithm?: string | undefined;
        digits?: number | undefined;
        period?: number | undefined;
    });
    /**
     * Account provider.
     * @type {string}
     */
    issuer: string;
    /**
     * Account label.
     * @type {string}
     */
    label: string;
    /**
     * Include issuer prefix in label.
     * @type {boolean}
     */
    issuerInLabel: boolean;
    /**
     * Secret key.
     * @type {Secret}
     */
    secret: Secret;
    /**
     * HMAC hashing algorithm.
     * @type {string}
     */
    algorithm: string;
    /**
     * Token length.
     * @type {number}
     */
    digits: number;
    /**
     * Token time-step duration.
     * @type {number}
     */
    period: number;
    /**
     * Calculates the counter. i.e. the number of periods since timestamp 0.
     * @param {Object} [config] Configuration options.
     * @param {number} [config.timestamp=Date.now] Timestamp value in milliseconds.
     * @returns {number} Counter.
     */
    counter({ timestamp }?: {
        timestamp?: number | undefined;
    }): number;
    /**
     * Calculates the remaining time in milliseconds until the next token is generated.
     * @param {Object} [config] Configuration options.
     * @param {number} [config.timestamp=Date.now] Timestamp value in milliseconds.
     * @returns {number} counter.
     */
    remaining({ timestamp }?: {
        timestamp?: number | undefined;
    }): number;
    /**
     * Generates a TOTP token.
     * @param {Object} [config] Configuration options.
     * @param {number} [config.timestamp=Date.now] Timestamp value in milliseconds.
     * @returns {string} Token.
     */
    generate({ timestamp }?: {
        timestamp?: number | undefined;
    }): string;
    /**
     * Validates a TOTP token.
     * @param {Object} config Configuration options.
     * @param {string} config.token Token value.
     * @param {number} [config.timestamp=Date.now] Timestamp value in milliseconds.
     * @param {number} [config.window=1] Window of counter values to test.
     * @returns {number|null} Token delta or null if it is not found in the search window, in which case it should be considered invalid.
     */
    validate({ token, timestamp, window }: {
        token: string;
        timestamp?: number | undefined;
        window?: number | undefined;
    }): number | null;
    /**
     * Returns a Google Authenticator key URI.
     * @returns {string} URI.
     */
    toString(): string;
}
import { Secret } from "./secret.js";
