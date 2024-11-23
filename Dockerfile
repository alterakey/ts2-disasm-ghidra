from python:3.11
run pip install flit
copy . /tmp/build/
run (cd /tmp/build && flit build)

from python:3.11
run apt-get update -y && apt-get -y install unzip zstd
run mkdir /app
run (cd /app; curl -Lo /tmp/ghidra.zip https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_10.3.3_build/ghidra_10.3.3_PUBLIC_20230829.zip && unzip -q /tmp/ghidra.zip && mv ghidra_* ghidra && rm /tmp/ghidra.zip)
run (cd /app; curl -L https://download.oracle.com/graalvm/22/latest/graalvm-jdk-22_linux-$(uname -m | sed -e 's/x86_64/x64/')_bin.tar.gz | gzip -dc | tar -x; mv graalvm* jvm)
env JAVA_HOME /app/jvm
# Building missing binary takes a long time so extract from the archive
add ghidra-10.3.3-natives-linux-arm64.tar.gz /app/ghidra/
# .. if you really prefer building it, comment above and uncomment below
#run (cd /app; curl -Lo /tmp/gradle.zip https://services.gradle.org/distributions/gradle-8.10-bin.zip && unzip -q /tmp/gradle.zip && rm /tmp/gradle.zip && mv gradle-* gradle)
#env PATH /bin:/sbin:/usr/bin:/usr/sbin:/app/jvm/bin:/app/gradle/bin
#run (cd /app/ghidra && ./support/buildNatives)

from python:3.11
run apt-get update -y && apt-get -y install unzip zstd
run mkdir /app /out /cache
copy --from=1 /app/ghidra /app/ghidra
copy --from=1 /app/jvm /app/jvm
env JAVA_HOME /app/jvm
copy --from=0 /tmp/build/dist/*.whl /tmp/dist/
run pip install /tmp/dist/*.whl && rm -rf /tmp/dist
run ln -sfn /usr/local/bin/disasm /app
env PATH /bin:/sbin:/usr/bin:/usr/sbin:/app:/app/jvm/bin
workdir /out
entrypoint ["disasm"]