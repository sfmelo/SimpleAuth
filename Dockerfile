### builder stage
FROM docker.io/python:3.10.6 AS builder

# Install pipenv
RUN pip install --user pipenv

# Tell pipenv to create venv in the current directory
ENV PIPENV_VENV_IN_PROJECT=1

# Add Pipfile and app to image 
ADD Pipfile Pipfile.lock /usr/src/

# Change work directory to where pipfile is
WORKDIR /usr/src

# Install packages in Pipfile
RUN /root/.local/bin/pipenv sync

# Check that packages are installed
RUN /usr/src/.venv/bin/python -c "import flask; print(flask.__version__)"

### runtime stage
FROM docker.io/python:3.10.6 AS runtime

# Create virtual environment folders
RUN mkdir -v /usr/src/.venv

# Copy virtual environment from builder stage
COPY --from=builder /usr/src/.venv /usr/src/.venv/

# Check that packages are installed
RUN /usr/src/.venv/bin/python -c "import flask; print(flask.__version__)"

# Add app to image
ADD app.py db.py config.example.json /usr/src/

WORKDIR /usr/src/

RUN mv config.example.json config.json

CMD ["./.venv/bin/python", "app.py"]