import datetime
import logging
import os
import sys

import plugins.helpers.chainbreaker as chainbreaker

logger = logging.getLogger(__name__)


def summary(args, keychain_md5, keychain_sha256):
    # Collect summary of information
    summary_output = [
        "Chainbreaker : https://github.com/n0fate/chainbreaker",
        #"Credits: Forked from https://github.com/n0fate/chainbreaker",
        #"Credits: Thanks to https://github.com/gaddie-3/chainbreaker",
        "Version: %s" % chainbreaker.__version__,
        "Runtime Command: %s" % ' '.join(sys.argv),
        "Keychain: %s" % args.keychain,
        "Keychain MD5: %s" % keychain_md5,
        "Keychain 256: %s" % keychain_sha256,
        "Dump Start: %s" % datetime.datetime.now(),
    ]

    # print / log summary of input
    for line in summary_output:
        logger.info(line)

    return summary_output


def resolve(args, keychain):
    output = []
    if args.dump_keychain_password_hash or args.export_keychain_password_hash:
        output.append(
            {
                'header': 'Keychain Password Hash',
                'records': [keychain.dump_keychain_password_hash()],  # A little hackish, but whatever.
                'write_to_console': args.dump_keychain_password_hash,
                'write_to_disk': args.export_keychain_password_hash,
                'write_directory': os.path.join(args.output),
            })

    if args.dump_generic_passwords or args.export_generic_passwords:
        output.append(
            {
                'header': 'Generic Passwords',
                'records': keychain.dump_generic_passwords(),
                'write_to_console': args.dump_generic_passwords,
                'write_to_disk': args.export_generic_passwords,
                'write_directory': os.path.join(args.output, 'passwords', 'generic'),
            })
    if args.dump_internet_passwords or args.export_internet_passwords:
        output.append(
            {
                'header': 'Internet Passwords',
                'records': keychain.dump_internet_passwords(),
                'write_to_console': args.dump_internet_passwords,
                'write_to_disk': args.export_internet_passwords,
                'write_directory': os.path.join(args.output, 'passwords', 'internet'),
            })
    if args.dump_appleshare_passwords or args.export_appleshare_passwords:
        output.append(
            {
                'header': 'Appleshare Passwords',
                'records': keychain.dump_appleshare_passwords(),
                'write_to_console': args.dump_appleshare_passwords,
                'write_to_disk': args.export_appleshare_passwords,
                'write_directory': os.path.join(args.output, 'passwords', 'appleshare'),
            })
    if args.dump_private_keys or args.export_private_keys:
        output.append(
            {
                'header': 'Private Keys',
                'records': keychain.dump_private_keys(),
                'write_to_console': args.dump_private_keys,
                'write_to_disk': args.export_private_keys,
                'write_directory': os.path.join(args.output, 'keys', 'private'),
            })
    if args.dump_public_keys or args.export_public_keys:
        output.append(
            {
                'header': 'Public Keys',
                'records': keychain.dump_public_keys(),
                'write_to_console': args.dump_public_keys,
                'write_to_disk': args.export_public_keys,
                'write_directory': os.path.join(args.output, 'keys', 'public'),
            })
    if args.dump_x509_certificates or args.export_x509_certificates:
        output.append(
            {
                'header': 'x509 Certificates',
                'records': keychain.dump_x509_certificates(),
                'write_to_console': args.dump_x509_certificates,
                'write_to_disk': args.export_x509_certificates,
                'write_directory': os.path.join(args.output, 'certificates'),
            })
    return output


def log_output(output, summary_output, args):
    # Print all parsed records from output until the end or until keyboard intterupt is given
    try:
        for record_collection in output:
            if 'records' in record_collection:
                collection_summary = "%s %s" % (len(record_collection['records']), record_collection['header'])
                logger.info(collection_summary)

                summary_output.append("\t%s" % collection_summary)

                for record in record_collection['records']:
                    if record_collection.get('write_to_console', False):
                        for line in str(record).split('\n'):
                            logger.info("\t%s" % line)
                    if record_collection.get('write_to_disk', False):
                        record.write_to_disk(record_collection.get('write_directory', args.output))
                    logger.info("")

        summary_output.append("Dump End: %s" % datetime.datetime.now())

        if any(x.get('write_to_disk', False) for x in output):
            with open(os.path.join(args.output, "summary.txt"), 'w') as summary_fp:
                for line in summary_output:
                    summary_fp.write("%s\n" % line)
                    logger.info(line)
        else:
            for line in summary_output:
                logger.info(line)

    except KeyboardInterrupt:
        exit(0)
