import time

import json
from joserfc.jwk import ECKey

if __name__ == "__main__":
    now = int(time.time())
    parameters = {"kid": f"cards-jwk-{now}"}
    key = ECKey.generate_key(
        "P-256", parameters=parameters, private=True
    )
    data = key.as_dict(private=True) 
    print(json.dumps(data))