import argparse
import getpass
import logging
import os

logger = logging.getLogger(__name__)


def setup_argsparse():
    arguments = argparse.ArgumentParser(description='Dump items stored in an OSX Keychain')

    # General Arguments
    arguments.add_argument('keychain', help='Location of the keychain file to parse')

    # Available actions
    dump_actions = arguments.add_argument_group('Dump Actions')
    dump_actions.add_argument('--dump-all', '-a', help='Dump records to the console window.',
                              action='store_const', dest='dump_all', const=True)
    dump_actions.add_argument('--dump-keychain-password-hash', help='Dump the keychain password'
                              'hash in a format suitable for hashcat or John The Ripper',
                              action='store_const', dest='dump_keychain_password_hash', const=True)
    dump_actions.add_argument('--dump-generic-passwords', help='Dump all generic passwords',
                              action='store_const', dest='dump_generic_passwords', const=True)
    dump_actions.add_argument('--dump-internet-passwords', help='Dump all internet passwords',
                              action='store_const', dest='dump_internet_passwords', const=True)
    dump_actions.add_argument('--dump-appleshare-passwords', help='Dump all appleshare passwords',
                              action='store_const', dest='dump_appleshare_passwords', const=True)
    dump_actions.add_argument('--dump-private-keys', help='Dump all private keys',
                              action='store_const', dest='dump_private_keys', const=True)
    dump_actions.add_argument('--dump-public-keys', help='Dump all public keys',
                              action='store_const', dest='dump_public_keys', const=True)
    dump_actions.add_argument('--dump-x509-certificates', help='Dump all X509 certificates',
                              action='store_const', dest='dump_x509_certificates', const=True)

    # Export private keys, public keys, or x509 certificates to disk.
    export_actions = arguments.add_argument_group('Export Actions',
                                                  description='Export records to files. Save location '
                                                              'is CWD, but can be overridden with --output / -o')

    export_actions.add_argument('--export-keychain-password-hash', help='Save the keychain password hash to disk',
                                action='store_const', dest='export_keychain_password_hash', const=True)
    export_actions.add_argument('--export-generic-passwords', help='Save all generic passwords to disk',
                                action='store_const', dest='export_generic_passwords', const=True)
    export_actions.add_argument('--export-internet-passwords', help='Save all internet passwords to disk',
                                action='store_const', dest='export_internet_passwords', const=True)
    export_actions.add_argument('--export-appleshare-passwords', help='Save all appleshare passwords to disk',
                                action='store_const', dest='export_appleshare_passwords', const=True)
    export_actions.add_argument('--export-private-keys', help='Save private keys to disk',
                                action='store_const', dest='export_private_keys', const=True)
    export_actions.add_argument('--export-public-keys', help='Save public keys to disk',
                                action='store_const', dest='export_public_keys', const=True)
    export_actions.add_argument('--export-x509-certificates', help='Save X509 certificates to disk',
                                action='store_const', dest='export_x509_certificates', const=True)
    export_actions.add_argument('--export-all', '-e',
                                help='Save records to disk',
                                action='store_const', dest='export_all', const=True)

    misc_actions = arguments.add_argument_group('Misc. Actions')

    misc_actions.add_argument('--check-unlock-options', '-c',
                              help='Only check to see if the provided unlock options work.'
                                   ' Exits 0 on success, 1 on failure.',
                              action='store_const', dest='check_unlock', const=True)

    # Keychain Unlocking Arguments
    unlock_args = arguments.add_argument_group('Unlock Options')
    unlock_args.add_argument('--password-prompt', '-p', help='Prompt for a password to use in unlocking the keychain',
                             action='store_const', dest='password_prompt', const=True)
    unlock_args.add_argument('--password', help='Unlock the keychain with a password, provided on the terminal.'
                                                'Caution: This is insecure and you should likely use'
                                                '--password-prompt instead')
    unlock_args.add_argument('--key-prompt', '-k', help='Prompt for a key to use in unlocking the keychain',
                             action='store_const', dest='key_prompt', const=True)
    unlock_args.add_argument('--key', help='Unlock the keychain with a key, provided via argument.'
                                           'Caution: This is insecure and you should likely use --key-prompt instead')
    unlock_args.add_argument('--unlock-file', help='Unlock the keychain with a key file')

    # Output arguments
    output_args = arguments.add_argument_group('Output Options')
    output_args.add_argument('--output', '-o', help='Directory to output exported records to.')
    output_args.add_argument('-d', '--debug', help="Print debug information", action="store_const", dest="loglevel",
                             const=logging.DEBUG)

    arguments.set_defaults(
        loglevel=logging.INFO,
        dump_all=False,
        dump_keychain_password_hash=False,
        dump_generic_passwords=False,
        dump_internet_passwords=False,
        dump_appleshare_passwords=False,
        dump_private_keys=False,
        dump_public_keys=False,
        dump_x509_certificates=False,
        export_keychain_password_hash=False,
        export_generic_passwords=False,
        export_internet_passwords=False,
        export_appleshare_passwords=False,
        export_private_keys=False,
        export_public_keys=False,
        export_x509_certificates=False,
        export_all=False,
        check_unlock=False,
        password_prompt=False,
        key_prompt=False,
        password=None,
        key=None,
        unlock_file=None,
    )

    return arguments.parse_args()


def set_output_dir(args, log):
    logger = log
    if args.output:
        if not os.path.exists(args.output):
            try:
                os.makedirs(args.output)
            except OSError:
                logger.critical("Unable to create output directory: %s" % args.output)
                exit(1)
        logger.addHandler(logging.FileHandler(os.path.join(args.output, 'output.log'), mode='w'))
        return args.output
    else:
        return os.getcwd()


def set_all_options_true(args):
    # If dump-all or export-all is set, set the individual args
    if args.dump_all:
        args.dump_keychain_password_hash = args.dump_generic_passwords = args.dump_internet_passwords = \
            args.dump_appleshare_passwords = args.dump_public_keys = args.dump_private_keys = \
            args.dump_x509_certificates = True

    if args.export_all:
        args.export_keychain_password_hash = args.export_generic_passwords = args.export_internet_passwords = \
            args.export_appleshare_passwords = args.export_public_keys = args.export_private_keys = \
            args.export_x509_certificates = True

    return args


def args_prompt_input(args):
    if args.password_prompt:
        args.password = getpass.getpass('Unlock Password: ')

    if args.key_prompt:
        args.key = getpass.getpass('Unlock Key: ')

    return args


def check_args_no_action(args):
    if not (args.check_unlock
            or args.dump_all
            or args.dump_appleshare_passwords
            or args.dump_generic_passwords
            or args.dump_internet_passwords
            or args.dump_keychain_password_hash
            or args.dump_private_keys
            or args.dump_public_keys
            or args.dump_x509_certificates
            or args.export_all
            or args.export_appleshare_passwords
            or args.export_generic_passwords
            or args.export_internet_passwords
            or args.export_keychain_password_hash
            or args.export_private_keys
            or args.export_public_keys
            or args.export_x509_certificates):
        logger.critical("No action specified.")
        exit(1)


def args_unlock_option(args, keychain):
    if args.check_unlock:
        if keychain.locked:
            logger.info("Invalid Unlock Options")
            exit(1)
        else:
            logger.info("Keychain Unlock Successful.")
            exit(0)
