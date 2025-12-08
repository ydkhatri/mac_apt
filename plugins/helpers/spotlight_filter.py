'''
   Copyright (c) 2020 Yogesh Khatri 

   This file is part of mac_apt (macOS Artifact Parsing Tool).
   Usage or distribution of this software/code is subject to the 
   terms of the MIT License.
   
'''

import logging
import os
import sqlite3

log = logging.getLogger('MAIN.HELPERS.SPOTLIGHT_FILTER')

def get_columns_with_data(db, bundle_id, table_name, columns_info):
    '''Given a bundle_id and table, this will filter out empty columns
       and return a list of column names that have data'''
    cols_with_data = []
    select_items = ''

    for c, c_type in columns_info.items():
        if c == bundle_id: continue
        if c_type == 'INTEGER':
            select_items += f'total("{c}") "{c}",'
        else: # c_type == 'TEXT':
            select_items += f'max("{c}") "{c}",'

    select_items = select_items.rstrip(',')

    query = f'SELECT {select_items} FROM "{table_name}" WHERE _kMDItemBundleID ="{bundle_id}"'
    cursor = db.execute(query)
    for row in cursor: # There will only be 1 row
        for c in columns_info:
            if c == bundle_id: continue
            data = row[c]
            if (data is None) or (data == 0.0) or (data == '') or \
               (data == '00' and c == "Parent_ID_hex"): # EMPTY col
                pass
            else:
                cols_with_data.append(c)

    #print (len(cols_with_data))
    cursor.close()
    return cols_with_data

def create_views_for_ios_db(path_to_db, base_table_name):

    if not os.path.exists(path_to_db):
        log.error(f'Error! File not found: {path_to_db}')
        return False

    db = sqlite3.connect(path_to_db)
    db.row_factory = sqlite3.Row

    # 1. Get Table fields/columns info
    columns_info = {}

    query = f'SELECT name, type FROM PRAGMA_TABLE_INFO("{base_table_name}")'
    try:
        cursor = db.execute(query)
        for row in cursor:
            columns_info[row['name']] = row['type']
        cursor.close()
    except sqlite3.Error as ex:
        log.exception(f"Error getting Table fields/columns info for table {base_table_name}")
        db.close()
        return False

    # 2. Get Bundle IDs and Content Types
    bundles = {}

    query = f'select _kMDItemBundleID, kMDItemContentType from "{base_table_name}" WHERE _kMDItemBundleID NOT LIKE "" GROUP BY _kMDItemBundleID, kMDItemContentType'
    try:
        cursor = db.execute(query)
        for row in cursor:
            existing = bundles.get(row['_kMDItemBundleID'], None)
            if existing:
                existing.append(row['kMDItemContentType'])
            else:
                bundles[row['_kMDItemBundleID']] = [row['kMDItemContentType']]
        cursor.close()
    except sqlite3.Error as ex:
        log.exception(f"Error getting bundle ids and content types for table {base_table_name}")
        db.close()
        return False

    # 3. For each bundleid, identify empty columns/fields

    bundles_with_column_info = {}
    for bundle_id in bundles:
        cols_with_data = get_columns_with_data(db, bundle_id, base_table_name, columns_info)
        bundles_with_column_info[bundle_id] = cols_with_data

    # # 4. Add separate table for each bundle
    #
    # for bundle_id, cols in bundles_with_column_info.items():
    #     selected_fields = ",".join([f'"{c}"' for c in cols])
    #     print(selected_fields)
    #     new_table_name = base_table_name + "_" + bundle_id
    #     query = f'CREATE TABLE {new_table_name} AS SELECT {selected_fields} FROM "Spotlight-store.db"'

    # 4. Add separate view for each bundle
    view_count = 0
    for bundle_id, cols in bundles_with_column_info.items():
        selected_fields = ",".join([f'"{c}"' for c in cols])
        new_table_name = base_table_name + "_" + bundle_id
        query = f'CREATE VIEW "{new_table_name}" AS SELECT {selected_fields} FROM "{base_table_name}" WHERE _kMDItemBundleId="{bundle_id}"'
        #print(query)
        try:
            db.execute(query)
            view_count += 1
        except sqlite3.Error as ex:
            log.exception(f"Error adding view for table {base_table_name}. Query was {query}")

    db.close()
    log.info(f"{view_count} views added for table {base_table_name}")
    return True