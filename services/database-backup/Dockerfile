FROM tiredofit/db-backup@sha256:0dc4cf2778c682928df2404319705c95514b00f093ad3eaac1e7bc756c630511

# Alpine 3.21 official package, inspected 2026-10-07. Do not upgrade the base.
ARG PG16_CLIENT_APK_VERSION=16.15-r0
RUN apk info -v | sort > /tmp/backup-base-packages.before \
 && apk add --no-cache "postgresql16-client=${PG16_CLIENT_APK_VERSION}" \
 && apk info -v | sort > /tmp/backup-base-packages.after \
 && comm -23 /tmp/backup-base-packages.before /tmp/backup-base-packages.after > /tmp/backup-base-packages.changed \
 && if [ -s /tmp/backup-base-packages.changed ]; then cat /tmp/backup-base-packages.changed; exit 1; fi \
 && rm /tmp/backup-base-packages.before /tmp/backup-base-packages.after /tmp/backup-base-packages.changed \
 && /usr/libexec/postgresql16/pg_dumpall --version \
 && /usr/libexec/postgresql16/pg_dump --version \
 && /usr/libexec/postgresql16/psql --version

# s6 supplies its own PATH to scheduled services. Select the complete client set
# in both contexts; pg_dumpall must find its matching pg_dump beside itself.
ENV PATH="/usr/local/libexec/pg-backup-guard:/usr/libexec/postgresql16:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
    S6_GLOBAL_PATH="/usr/local/libexec/pg-backup-guard:/usr/libexec/postgresql16:/command:/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin:/usr/local/sbin"

COPY pg-dumpall-guard.py /usr/local/libexec/pg-backup-guard/pg_dumpall
COPY patch-native-hooks.py /usr/local/libexec/patch-native-hooks.py
COPY recovery-bundle.py /usr/local/libexec/recovery-bundle.py
COPY post-nas.sh post-s3.sh /assets/database-recovery/
RUN python3 /usr/local/libexec/patch-native-hooks.py \
 && chmod 0755 /usr/local/libexec/recovery-bundle.py /usr/local/libexec/pg-backup-guard/pg_dumpall \
 && chmod 0755 /assets/database-recovery/post-nas.sh /assets/database-recovery/post-s3.sh \
 && ln -s /usr/local/libexec/pg-backup-guard/pg_dumpall /usr/local/bin/pg_dumpall \
 && for command in pg_dump psql pg_restore pg_isready; do ln -s "/usr/libexec/postgresql16/$command" "/usr/local/bin/$command"; done
