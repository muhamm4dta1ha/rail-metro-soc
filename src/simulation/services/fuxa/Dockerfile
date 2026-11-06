# FUXA (frangoteam/fuxa) ships Modbus support as an npm plugin it tries to self-install at
# runtime - which needs internet access FUXA's container never has, since every lab zone is
# `internal: true` (HC-18). Pre-installing it here, at build time (when the Docker build step
# *can* reach the real npm registry), gives FUXA the same package without ever needing internet
# access once the container is actually running in the lab.
FROM frangoteam/fuxa:1.3.5

WORKDIR /usr/src/app/FUXA/server
RUN npm install --no-save modbus-serial@8.0.19
