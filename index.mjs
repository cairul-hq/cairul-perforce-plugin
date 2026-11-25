import { execFile } from 'node:child_process';
import { env } from 'node:process';
import { promisify } from 'node:util';
import {
  basic,
  bearer,
  check,
  connection,
  envName,
  environment,
  matchesState,
  positiveID,
  secretPath,
  segment,
  setting,
  service,
  stateOption,
  text,
  verdict,
  z,
} from '@cairul/pdk';

const exec = promisify(execFile);

export default function perforce(options = {}) {
  const settings = z
    .strictObject({
      executable: text.optional(),
      authMode: text.optional(),
      baseUrl: z.url({ protocol: /^https?$/ }).optional(),
      tokenEnv: envName.optional(),
      tokenFile: secretPath.optional(),
      email: text.optional(),
      port: text.optional(),
      user: text.optional(),
      client: text.optional(),
      ticketsFile: secretPath.optional(),
      config: text.optional(),
    })
    .parse(options);
  const prefix = 'PERFORCE';
  const executable = setting(prefix, 'EXECUTABLE', settings.executable ?? 'p4');
  const baseUrl = setting(prefix, 'BASE_URL', settings.baseUrl);
  const native = { ...env };
  for (const [variable, suffix, fallback] of [
    ['P4PORT', 'PORT', settings.port],
    ['P4USER', 'USER', settings.user],
    ['P4CLIENT', 'CLIENT', settings.client],
    ['P4TICKETS', 'TICKETS_FILE', settings.ticketsFile],
    ['P4CONFIG', 'CONFIG', settings.config],
    ['P4PASSWD', 'PASSWORD', undefined],
    ['P4LOGINSSO', 'LOGIN_SSO', undefined],
    ['P4TRUST', 'TRUST_FILE', undefined],
  ]) {
    const value = setting(prefix, suffix, environment(variable) ?? fallback);
    if (value) native[variable] = value;
  }
  const review =
    baseUrl &&
    connection(
      {
        baseUrl,
        authMode: settings.authMode,
        tokenEnv: settings.tokenEnv,
        tokenFile: settings.tokenFile,
        email: settings.email,
      },
      {
        prefix,
        baseUrl,
        tokenEnv: 'P4_REVIEW_TOKEN',
        required: true,
        authModes: { basic, bearer },
        defaultAuth: (username) => (username ? 'basic' : 'bearer'),
      }
    );
  async function p4(args, { projectDir, signal }) {
    let stdout;
    try {
      ({ stdout } = await exec(executable, ['-Mj', '-ztag', ...args], {
        cwd: projectDir,
        env: native,
        signal,
        maxBuffer: 2 * 1024 * 1024,
      }));
    } catch {
      throw new Error('P4 command failed. Check the client configuration and permissions.');
    }
    const records = stdout.trim()
      ? stdout
          .trim()
          .split(/\r?\n/)
          .map((line) => JSON.parse(line))
      : [];
    if (records.some((record) => record.code === 'error' || Number(record.severity) >= 3))
      throw new Error('P4 returned an error.');
    return records;
  }
  const change = z.strictObject({ change: positiveID });
  return {
    checkKinds: {
      'perforce.changelist-submitted': check(change, ({ change }, context) =>
        service(async () => {
          const [record] = await p4(['describe', '-s', change], context);
          return matchesState(record?.status, 'submitted', 'Changelist');
        })
      ),
      'perforce.changelist-shelved': check(change, ({ change }, context) =>
        service(async () => {
          const [record] = await p4(['changes', '-r', '-e', change, '-s', 'shelved', '-m', '1'], context);
          return verdict(String(record?.change) === change, `Waiting for shelved changelist ${change}.`);
        })
      ),
      'perforce.job-linked': check(change.extend({ job: text }), ({ change, job }, context) =>
        service(async () => {
          const fixes = await p4(['fixes', '-c', change], context);
          return verdict(
            fixes.some((fix) => (fix.Job ?? fix.job) === job),
            'Waiting for job to be linked to the changelist.'
          );
        })
      ),
      'perforce.review-state': check(
        z.strictObject({ review: positiveID, state: stateOption.default('approved') }),
        ({ review: id, state }, { signal }) =>
          service(async () => {
            if (!review) throw new Error('Set plugin options.baseUrl to the P4 Code Review API root.');
            return matchesState(
              (await review.request(`reviews/${segment(id)}`, { signal })).review?.state,
              state,
              'Review'
            );
          })
      ),
    },
  };
}
