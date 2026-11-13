// The Worker under test: the app and the Scanner built around the tests' config.
import { makeWorker } from "../src/app.js";
import { scannerClass } from "../src/scanner.js";
import { TEST_CONFIG } from "./config.js";

export default makeWorker(TEST_CONFIG);
export const Scanner = scannerClass(TEST_CONFIG);
