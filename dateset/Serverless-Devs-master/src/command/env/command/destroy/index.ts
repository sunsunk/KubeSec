import { Command } from 'commander';
import chalk from 'chalk';
import { emoji } from '@/utils';
import Action from './action';

const description = `Delete specified env.

Supported vendors: Alibaba Cloud

    Example:
        $ s env destroy --name test-env

${emoji('📖')} Document: ${chalk.underline('https://serverless.help/t/s/env')}`;

export default (program: Command) => {
  const command = program.command('destroy');
  command
    .usage('[options]')
    .description(description)
    .summary(`Delete specified environment`)
    .requiredOption('-n, --name <name>', 'Env name')
    .helpOption('-h, --help', 'Display help for command')
    .action(async options => {
      await new Action({ ...options, ...program.optsWithGlobals() }).start();
    });
};
