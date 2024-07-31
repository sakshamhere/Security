list of instructions in the Dockerfile:
- ARG
- FROM
- RUN
- ADD
- COPY
- ENV
- EXPOSE
- LABEL
- STOPSIGNAL
- USER
- VOLUME
- WORKDIR
- ONBUILD (when combined with one of the supported instructions above)


# FROM
- As such, a valid Dockerfile must start with a FROM instruction. 
- The image can be any valid image – it is especially easy to start by pulling an image from the Public Repositories.
- FROM can appear multiple times within a single Dockerfile to create multiple images or use one build stage as a dependency for another.

* ARG
ARG is the only instruction that may precede FROM in the Dockerfile

how ARG and FROM interact- FROM instructions support variables that are declared by any ARG instructions that occur before the first FROM.

ex -

ARG  CODE_VERSION=latest
FROM base:${CODE_VERSION}
CMD  /code/run-app

FROM extras:${CODE_VERSION}
CMD  /code/run-extras

* An ARG declared before a FROM is outside of a build stage, so it can’t be used in any instruction after a FROM
To use the default value of an ARG declared before the first FROM use an ARG instruction without a value inside of a build stage:

ARG VERSION=latest
FROM busybox:$VERSION
ARG VERSION
RUN echo $VERSION > image_version
*************************************************************************************************************************
# ARG

A Dockerfile may include one or more ARG instructions. For example, the following is a valid Dockerfile:

FROM busybox
ARG user1
ARG buildno

An ARG instruction can optionally include a default value:

FROM busybox
ARG user1=someuser
ARG buildno=1

NOTE - Environment variables defined using the ENV instruction always override an ARG instruction of the same name. Consider this Dockerfile with an ENV and ARG instruction.

FROM ubuntu
ARG CONT_IMG_VER
ENV CONT_IMG_VER=v1.0.0
RUN echo $CONT_IMG_VER
Then, assume this image is built with this command:

docker build --build-arg CONT_IMG_VER=v2.0.1 .

In this case, the RUN instruction uses v1.0.0 instead of the ARG setting passed by the user:v2.0.1 This behavior is similar to a shell script where a locally scoped variable overrides the variables passed as arguments or inherited from environment, from its point of definition.

*************************************************************************************************************************
# Predefined ARGs
Docker has a set of predefined ARG variables that you can use without a corresponding ARG instruction in the Dockerfile.

HTTP_PROXY
http_proxy
HTTPS_PROXY
https_proxy
FTP_PROXY
ftp_proxy
NO_PROXY
no_proxy
ALL_PROXY
all_proxy
To use these, pass them on the command line using the --build-arg flag, for example:

 docker build --build-arg HTTPS_PROXY=https://my-proxy.example.com .

************************************************************************************************************************
# RUN
The RUN instruction will execute any commands in a new layer on top of the current image and commit the results.
The resulting committed image will be used for the next step in the Dockerfile.

RUN has 2 forms:

- RUN <command> (shell form, the command is run in a shell, which by default is /bin/sh -c on Linux or cmd /S /C on Windows)

- RUN ["executable", "param1", "param2"] (exec form)

ex - 

RUN /bin/bash -c 'source $HOME/.bashrc; echo $HOME'

RUN ["/bin/bash", "-c", "echo hello"]
***********************************************************************************************************************

# CMD
The main purpose of a CMD is to provide defaults for an executing container. 
These defaults can include an executable, or they can omit the executable, in which case you must specify an ENTRYPOINT instruction as well.
There can only be one CMD instruction in a Dockerfile. If you list more than one CMD then only the last CMD will take effect.

The CMD instruction has three forms:

- CMD ["executable","param1","param2"] (exec form, this is the preferred form)
- CMD ["param1","param2"] (as default parameters to ENTRYPOINT)
- CMD command param1 param2 (shell form)

* ENTRYPOINT

If you would like your container to run the same executable every time, then you should consider using ENTRYPOINT in combination with CMD

NOTE - Do not confuse RUN with CMD. RUN actually runs a command and commits the result; CMD does not execute anything at build time, but specifies the intended command for the image.

If the user specifies arguments to docker run then they will override the default specified in CMD.

ex - 

FROM ubuntu
CMD echo "This is a test." | wc 

FROM ubuntu
CMD ["/usr/bin/wc","--help"]
*********************************************************************************************************************
# ENTRYPOINT
ENTRYPOINT has two forms:

The exec form, which is the preferred form:

- ENTRYPOINT ["executable", "param1", "param2"]

The shell form:

- ENTRYPOINT command param1 param2

You can override the ENTRYPOINT instruction using the docker run --entrypoint flag.

# https://www.youtube.com/watch?v=OYbEWUbmk90

# LABEL
The LABEL instruction adds metadata to an image.
A LABEL is a key-value pair.
An image can have more than one label. You can specify multiple labels on a single line.
Labels included in base or parent images (images in the FROM line) are inherited by your image

ex 
LABEL "com.example.vendor"="ACME Incorporated"
LABEL com.example.label-with-value="foo"
LABEL version="1.0"
LABEL description="This text illustrates \
that label-values can span multiple lines."

LABEL multi.label1="value1" multi.label2="value2" other="value3"

LABEL multi.label1="value1" \
      multi.label2="value2" \
      other="value3"


To view an image’s labels, use the docker image inspect command. You can use the --format option to show just the labels;

 docker image inspect --format='' myimage
*************************************************************************************************************************

# EXPOSE
The EXPOSE instruction informs Docker that the container listens on the specified network ports at runtime.
You can specify whether the port listens on TCP or UDP, and the default is TCP if the protocol is not specified.

By default, EXPOSE assumes TCP. You can also specify UDP:

EXPOSE 80/udp

To expose on both TCP and UDP, include two lines:

EXPOSE 80/tcp
EXPOSE 80/udp

The EXPOSE instruction does not actually publish the port. To actually publish the port when running the container, use the -p flag on docker run to publish and map one or more ports, or the -P flag to publish all exposed ports and map them to high-order ports.

Regardless of the EXPOSE settings, you can override them at runtime by using the -p flag. For example

 docker run -p 80:80/tcp -p 80:80/udp ...
***********************************************************************************************************************

# ENV
The ENV instruction sets the environment variable <key> to the value <value>
This value will be in the environment for all subsequent instructions in the build stage and can be replaced inline in many as well.

Like command line parsing, quotes and backslashes can be used to include spaces within values.

ENV MY_NAME="John Doe"
ENV MY_DOG=Rex\ The\ Dog
ENV MY_CAT=fluffy


The ENV instruction allows for multiple <key>=<value> ... variables to be set at one time

ENV MY_NAME="John Doe" MY_DOG=Rex\ The\ Dog \
    MY_CAT=fluffy

NOTE - The environment variables set using ENV will persist when a container is run from the resulting image, 

You can view the values using docker inspect, and change them using docker run --env <key>=<value>.

Environment variable persistence can cause unexpected side effects. 

For example, setting ENV DEBIAN_FRONTEND=noninteractive changes the behavior of apt-get, and may confuse users of your image.

If an environment variable is only needed during build, and not in the final image, consider using RUN or ARG 

RUN DEBIAN_FRONTEND=noninteractive apt-get update && apt-get install -y ...

or

ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y ...
**********************************************************************************************************************

# ADD
The ADD instruction copies new files, directories or remote file URLs from <src> and adds them to the filesystem of the image at the path <dest>.
The <dest> is an absolute path, or a path relative to WORKDIR, into which the source will be copied inside the destination container.

Multiple <src> resources may be specified

ex

The example below uses a relative path, and adds “test.txt” to <WORKDIR>/relativeDir/:

- ADD test.txt relativeDir/

Whereas this example uses an absolute path, and adds “test.txt” to /absoluteDir/

- ADD test.txt /absoluteDir/

To add all files starting with “hom”:

- ADD hom* /mydir/

In the example below, ? is replaced with any single character, e.g., “home.txt”.

- ADD hom?.txt /mydir/

ADD obeys the following rules:

- The <src> path must be inside the context of the build.

- If <src> is a URL and <dest> does not end with a trailing slash, then a file is downloaded from the URL and copied to <dest>.

- If <src> is a URL and <dest> does end with a trailing slash, then the filename is inferred from the URL and the file is downloaded to <dest>/<filename>. For instance, ADD http://example.com/foobar / would create the file /foobar.

- If <src> is a directory, the entire contents of the directory are copied, including filesystem metadata.

- If multiple <src> resources are specified, either directly or due to the use of a wildcard, then <dest> must be a directory, and it must end with a slash /.

- If <dest> does not end with a trailing slash, it will be considered a regular file and the contents of <src> will be written at <dest>

- If <dest> doesn’t exist, it is created along with all missing directories in its path.
*******************************************************************************************************************

# COPY
The COPY instruction copies new files or directories from <src> and adds them to the filesystem of the container at the path <dest>.

To add all files starting with “hom”:

- COPY hom* /mydir/

In the example below, ? is replaced with any single character, e.g., “home.txt”.

- COPY hom?.txt /mydir/

The example below uses a relative path, and adds “test.txt” to <WORKDIR>/relativeDir/:

- COPY test.txt relativeDir/

Whereas this example uses an absolute path, and adds “test.txt” to /absoluteDir/

- COPY test.txt /absoluteDir/


* COPY --link

Enabling this flag in COPY or ADD commands allows you to copy files with enhanced semantics where your files remain independent on their own layer and don’t get invalidated when commands on previous layers are changed.

When --link is used your source files are copied into an empty destination directory. That directory is turned into a layer that is linked on top of your previous state.
********************************************************************************************************************

# VOLUME
The VOLUME instruction creates a mount point with the specified name and marks it as holding externally mounted volumes from native host or other containers


FROM ubuntu
RUN mkdir /myvol
RUN echo "hello world" > /myvol/greeting
VOLUME /myvol

# USER
The specified user is used for RUN instructions and at runtime, runs the relevant ENTRYPOINT and CMD commands.

FROM microsoft/windowsservercore
                            // Create Windows user in the container
RUN net user /add patrick
                            //Set it for subsequent commands
USER patrick

# WORKDIR

WorkDIR is similar to cd

The WORKDIR instruction sets the working directory for any RUN, CMD, ENTRYPOINT, COPY and ADD instructions that follow it in the Dockerfile. 

If the WORKDIR doesn’t exist, it will be created even if it’s not used in any subsequent Dockerfile instruction.

The WORKDIR instruction can be used multiple times in a Dockerfile. If a relative path is provided, it will be relative to the path of the previous WORKDIR instruction. For example:

WORKDIR /a
WORKDIR b
WORKDIR c
RUN pwd

The output of the final pwd command in this Dockerfile would be /a/b/c.

The WORKDIR instruction can resolve environment variables previously set using ENV. You can only use environment variables explicitly set in the Dockerfile. For example:

ENV DIRPATH=/path
WORKDIR $DIRPATH/$DIRNAME
RUN pwd

The output of the final pwd command in this Dockerfile would be /path/$DIRNAME

***********************************************************************************************************************
# ONBUILD

# STOPSIGNAL

# HEALTHCHECK

# SHELL