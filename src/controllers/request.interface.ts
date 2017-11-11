import express = require('express');

export interface IRequestWithUserId extends express.Request {
    userId: string;
}
