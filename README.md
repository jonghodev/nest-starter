## Description

Nest Starter

## Installation

```bash
$ yarn
```

## Running the app

```bash
# development
$ yarn start:dev:no-watch

# watch mode
$ yarn start:dev

# production mode1
$ yarn start:prod

# run build file
$ yarn start
```

## Test

https://github.com/jmcdo29/testing-nestjs/blob/master/apps/mongo-sample/src/cat/cat.controller.spec.ts

```bash
# unit tests
$ yarn test

# e2e tests
$ yarn test:e2e

# test coverage
$ yarn test:cov
```

## Environment

copy .env.sample to .env.development, .env.production

## REST API Speicifiation

### Success

Spec

```javascript
{
  success: boolean;
  message: string;
  data: any; // nullable
}
```

Example

```json
{
  "success": true,
  "message": "signup success",
  "data": {
    "id": 1,
    "email": "jongho.dev@gmail.com"
  }
}
```

```json
{
  "success": true,
  "message": "logout success"
}
```

Reference: https://github.com/omniti-labs/jsend

### Failure

Spec

```javascript
{
  success: boolean;
  statusCode: number;
  timestamp: string;
  path: string;
  error: string;
}
```

Example

```json
{
  "success": false,
  "statusCode": 404,
  "timestamp": "2020-12-07T02:01:34.643Z",
  "path": "/auth/login/email",
  "error": "Cannot POST /auth/hello"
}
```
