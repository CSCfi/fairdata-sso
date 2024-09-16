[![pipeline status](https://gitlab.ci.csc.fi/fairdata/fairdata-sso/badges/test/pipeline.svg)](https://gitlab.ci.csc.fi/fairdata/fairdata-sso/-/commits/test)

This is the implementation of the Fairdata SSO service.

See the swagger documentation for
detailed information regarding the service and API, available via the API endpoint `/swagger`
after successful deployment, or `swagger/swagger.html` locally.

# Configuration

Standard practice is for the repository to be cloned into the directory `/var/fairdata-sso`.

Python3 must be installed, and a virtual environment initialized by running the script

    utils/initialize-venv

A configuration file `config.json` must be created, defining the essential configuration
variables for the service. See the example file templates/config.json

A SAML settings file `saml.json` must be created, defining the essential SAML2 settings for the
service. See the example file templates/saml.json

After all of the above is done, setup as a service is done once by running the script

    utils/initialize-service

which also will run the `initialize-venv` script.

The service can be managed using the `systemctl` command. E.g.:
```
systemctl status fairdata-sso
systemctl start fairdata-sso
systemctl stop fairdata-sso
systemctl restart fairdata-sso
```

## Enabled Identity Providers

An optional variable IDENTITY_PROVIDERS can be defined in config.json, which takes an array of identity provider token strings.

If not defined, it defaults to the array [ "CSCID", "HAKA", "VIRTU" ]

In environments which only support a subset of identity providers, e.g. DEMO, the variable can be defined in config.json accordingly, e.g.
```
    "IDENTITY_PROVIDERS": [ "CSCID" ],
```

The allowed identity providers for each service, as defined in services.json, need not be modified in order to enable a subset of identity providers for a given environment. Even if a service allows an identity provider, if it is not defined in the IDENTITY_PROVIDERS array in config.json, it will not be offered to the user for validation.

# Dependency management

## Managing Python Dependencies

This repository uses Poetry for managing Python dependencies securely. Poetry generates very strict requirements.txt files, while enabling easy update of minor security and bug patches from pip with `pyproject.toml` defined version constraints. Generated requirements.txt is guaranteed to lock all dependencies and sub-dependencies. Poetry file `poetry.lock` stores hashes of all dependencies, if the integrity of the dependency-tree ever needs to be verified. 

For full documentation of Poetry, visit the [official documentation](https://python-poetry.org/docs/)

### Install Poetry

First, install [pipx](https://github.com/pypa/pipx). Pipx is a system-wide Python application installer, that creates virtualenv for every package installed and automatically includes them to path. It can also uninstall any package installed using pipx.  With pipx installed, install Poetry with `pipx install poetry`. After installation, you will have poetry available system-wide. 

### Installing dependencies

With virtualenv activated, you can install dependencies either with `pip install -r requirements.txt` or `poetry install`, if you have poetry in the system path.

### Adding dependencies

Adding a dependency will automatically add the dependency to the `pyproject.toml` and `poetry.lock` files. 

#### Adding normal dependency and updating requirements.txt
```
# Add new dependency
poetry add {{ dependency }}

# Update requirements.txt
poetry export --without-hashes -o requirements.txt
```

### Removing dependencies

```
# Remove dependency
poetry remove {{ dependency }}

# Remove development dependency
poetry remove -D {{ dependency }}
```

### Updating dependencies

Use `poetry update` to update all dependencies, respecting the version constraints set in `pyproject.toml` file.

### Updating the pyproject.toml manually

If you need to change any definitions in pyproject.toml, run `poetry update` after any changes. This will install any changed package version and update `poetry.lock` file.

# Development with Docker (Linux / Mac)

Repository includes assets for setting up local development environment with
Docker. Follow the instructions below to setup a local development environment
using domain `sso.fd-dev.csc.fi`.

## Prerequisites

These instructions assume that necessary configuration files are available on
the workstation. See section `Docker configs` below.

## Update etc/hosts

Append the following entry to your workstations `/etc/hosts` file:

```
0.0.0.0 sso.fd-dev.csc.fi
```

## Docker image

Docker image can either be built locally or pulled from docker registry. Stack
template uses private registry url, which should be available for internal
development.

If using local images, build the docker image for fairdata-sso by running the
following command at the repository root:

```
docker build --no-cache . -t fairdata-docker.artifactory.ci.csc.fi/fairdata-sso
```

## Docker configs

Once certificates and nginx configuration are available, create needed docker
configs in repository `fairdata-docker`:

```
docker stack deploy -c sso/docker-compose.dev.yml fairdata-conf
docker stack deploy -c tls/docker-compose.dev.yml fairdata-conf
```

## Docker stack

If not already started, start a new Docker Swarm cluster:

```
docker swarm init
```

Deploy application stack using the previously built image:

```
docker stack deploy --with-registry-auth --resolve-image always -c docker-compose.yml fairdata-sso
```

## Verify installation

Swagger ui for local development environment with the above configuration
should be accessible by visiting [https://sso.fd-dev.csc.fi/](https://sso.fd-dev.csc.fi/).
