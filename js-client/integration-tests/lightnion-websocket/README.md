# Integration Tests for Lightnion WebSocket

## Requirements

- Install [geckodriver](https://github.com/mozilla/geckodriver/releases) and add it to your PATH.
- Install `Tor` of version `0.3` (should be compatible with `lightnion`), instructions can be found [here](https://trac.torproject.org/projects/tor/wiki/TorRelayGuide#PlatformspecificInstructions).
- Install python requirements:
```bash
pip install -r requirements.txt
```
- Install infrastructure dependencies:
```bash
cd ../.. && make integration
```
# Running the tests

```bash
python run_integration_test.py
``` 

Logs for `chutney` and `lightnion` will be found in `tests/logs`.

## Notes

### Troubleshooting

- Launching chutney may fail because of paths being too long for unix socket. A solution is to move the project folder to a low level path like `/tmp`.

### Infrastructure Components

- `client`: a web browser client (selenium with geckodriver)
- `proxy`: a lightnion proxy
- `testnet`: a `testnet` simulated Tor network (chutney)
- `endpoint`: an endpoint for the websocket connection, the http server for the webpage and the lightnion code
