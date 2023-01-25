#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#
# (c) 2021 Arnim Eijkhoudt (arnime <thingamajic> kpn-cert.nl), GPLv3
#
# Please note: the MITRE ATT&CK® framework is a registered trademark
# of MITRE. See https://attack.mitre.org/ for more information.
#
# I would like to thank MITRE for the permissive licence under which
# ATT&CK® is available.
#

import argparse
import collections
import itertools
import logging
import json
import pathlib
import pprint
import shutil
import string
import urllib.request
import uvicorn
from config import settings as options
from config.matrixtable import Matrices
from fastapi import FastAPI, HTTPException, Request, Query
from fastapi.responses import JSONResponse, RedirectResponse
from typing import Optional


typemap = collections.OrderedDict({
    'intrusion-set': 'Actors',
    'campaign': 'Campaigns',
    'malware': 'Malwares',
    'course-of-action': 'Mitigations',
    'x-mitre-tactic': 'Tactics',
    'attack-pattern': 'Techniques',
    'tool': 'Tools',
    'uid': 'UID',
})
categories=[
    'Actors',
    'Campaigns',
    'Malwares',
    'Matrices',
    'Mitigations',
    'Tactics',
    'Techniques',
    'Tools'
]
tags_metadata = [
    {
        'name': 'docs',
        'description': 'This documentation.',
    },
    {
        'name': 'explore',
        'description': 'Basic interface for exploring the loaded MITRE ATT&CK® matrices. Returns a raw view of everything '
                       'under *treepath*, including all empty branches. **WARNING**: Can result in a lot of output!'
                       '<br /><br />'
                       '[Example query]'
                       '(http://' + options.ip + ':' + str(options.port) + '/api/explore/Actors/G0005) '
                       'to display all information about the *Actor G0005*.',
    },
    {
        'name': 'search',
        'description': 'Does a case-insensitive *LOGICAL AND search for all params fields in all entity names, urls and '
                       'descriptions, and returns a list of matching entities in all loaded MITRE ATT&CK® matrices.'
                       '<br /><br />'
                       '[Example query]'
                       '(http://' + options.ip + ':' + str(options.port) +
                       '/api/search?params=dragon&params=capture&params=property) '
                       'to find all entities with the words *dragon*, *capture* and *property* in all ATT&CK matrices.',
    },
    {
        'name': 'actoroverlap',
        'description': 'Finds the overlapping TTPs (*Malwares, Mitigations, Techniques, etc.*) for '
                       'two actors. Returns a list of Actors, a list of matrices they were found in, and *only* the TTPs '
                       'that overlapped (with their names/descriptions). Finding the TTPs that do not overlap can be '
                       'relatively trivially done through programmatical means, by pulling the complete Actor records '
                       'using the `/explore/` API endpoint and comparing the results for every actor with the overlapping '
                       'TTPs logically (`<Overlapping TTPs> NOT <actor\'s TTPs>`) to find the remaining TTPs per actor.'
                       '<br /><br />'
                       '[Example query]'
                       '(http://' + options.ip + ':' + str(options.port) + '/api/actoroverlap?actors=G0064&actors=G0050)'
                       ' to find the overlapping TTPs of *Actors G0064* and *G0050*.',
    },
    {
        'name': 'ttpoverlap',
        'description': 'Finds all actors that have a specific set of TTPs (*Malwares, (Sub)Techniques, Techniques '
                       'and Tools*). The number of TTPs can be varied, i.e.: 1 ... n fields can be given. Returns '
                       'the matching Actors with all of their ATT&CK® entity types (including names/descriptions).'
                       '<br /><br />'
                       '[Example query]'
                       '(http://' + options.ip + ':' + str(options.port) + '/api/ttpoverlap?ttp=S0002&ttp=S0008&ttp=T1560.001) '
                       'to find which *Actors* use *Tool S0002*, *Tool S0008* and *Technique T1560.001*.',
    },
]
app = FastAPI(title='MITRE ATT&CK Matrix API', openapi_tags=tags_metadata)


@app.get('/', tags=['docs'])
async def read_root():
    return RedirectResponse('/docs')


@app.get('/api/', tags=['docs'])
async def read_api():
    return RedirectResponse('/docs')


@app.get('/api/explore/{treepath:path}', tags=['explore'])
async def query(request: Request,
                token: Optional[str] = None):
    if options.token:
        if token != options.token:
            raise HTTPException(status_code=403, detail='Access denied: missing or incorrect token')
    try:
        results = {}
        cache = loadCache(options)
        if not request.path_params['treepath']:
            results = {
                'Metadata': {
                    'name': 'AttackMatrix API',
                    'description': 'Available keys: ' + ', '.join(key for key in cache),
                    'matrices': cache['Matrices'],
                },
            }
        else:
            treepath = request.path_params['treepath'].split('/')
            results = cache[treepath[0]][treepath[1]] if len(treepath)>1 else cache[treepath[0]]
    except KeyError:
        return None
    finally:
        return JSONResponse(results)


@app.get('/api/search', tags=['search'])
async def searchParam(request: Request,
                      params: list = Query([]),
                      token: Optional[str] = None):
    if options.token:
        if token != options.token:
            raise HTTPException(status_code=403, detail='Access denied: missing or incorrect token')
    return search(options, params)

@app.get('/api/actoroverlap', tags=['actoroverlap'])
async def actorOverlap(request: Request,
                       actors: list = Query([]),
                       token: Optional[str] = None):
    if options.token:
        if token != options.token:
            raise HTTPException(status_code=403, detail='Access denied: missing or incorrect token')
    return findActorOverlap(options, actors)


@app.get('/api/ttpoverlap', tags=['ttpoverlap'])
async def ttpOverlap(request: Request,
                     ttps: list = Query([]),
                     token: Optional[str] = None):
    if options.token:
        if token != options.token:
            raise HTTPException(status_code=403, detail='Access denied: missing or incorrect token')
    return findTTPOverlap(options, ttps)


def findActorOverlap(options, actors=[]):
    try:
        response = {}
        if not len(actors)>1:
            response = {
                'name': 'API Error',
                'description': 'Specify at least two Actors to check for overlap!'
            }
        else:
            cache = loadCache(options)
            response = collections.defaultdict(lambda: {}, {})
            ttps = {}
            for actor in actors:
                response[actor] = {}
                for category in categories:
                    if category in cache['Actors'][actor]:
                        for ttp in cache['Actors'][actor][category]:
                            if not category in ttps:
                                ttps[category] = {}
                            ttps[category][ttp] = cache['Actors'][actor][category][ttp]
            # Wipe TTP categories and types that do not appear in all actors
            for ttpcategory in list(ttps):
                for ttp in list(ttps[ttpcategory]):
                    for actor in actors:
                        if ttpcategory in cache['Actors'][actor]:
                            if not ttp in cache['Actors'][actor][ttpcategory]:
                                if ttp in ttps[ttpcategory]:
                                    del ttps[ttpcategory][ttp]
                        else:
                            if ttpcategory in ttps:
                                del ttps[ttpcategory]
            count = 0
            for actor in actors:
                for ttpcategory in ttps:
                    if len(ttps[ttpcategory])>0:
                        response[actor][ttpcategory] = ttps[ttpcategory]
                        count += len(ttps[ttpcategory])
                response[actor]['Metadata'] = cache['Actors'][actor]['Metadata']
            response['count'] = count/len(actors)
    except Exception as e:
            response = {
                'name': 'Python Error',
                'description': str(type(e))+': '+str(e),
            }
    finally:
        return response


def findTTPOverlap(options, ttps=[]):
    try:
        response = {}
        if not len(ttps)>1:
            response = {
                'name': 'API Error',
                'description': 'Specify at least two TTPs to check for overlap!'
            }
        else:
            cache = loadCache(options)
            response = {}
            for actor in cache['Actors']:
                actorttps = []
                response[actor] = {}
                for category in categories:
                    if category in cache['Actors'][actor]:
                        actorttps += list(cache['Actors'][actor][category])
                if set(ttps).issubset(actorttps):
                    response[actor] = cache['Actors'][actor]
                else:
                    del response[actor]
    except Exception as e:
            response = {
                'name': 'Python Error',
                'description': str(type(e))+': '+str(e),
            }
            response['count'] = count/len(actors)
    finally:
        return response


def search(options, params=[]):
    try:
        response = {}
        if not len(params):
            response = {
                'name': 'API Error',
                'description': 'Specify at least one search parameter!'
            }
        else:
            cache = loadCache(options)
            response = collections.defaultdict(lambda: {})
            for category in categories:
                for object in cache[category]:
                    metadata = cache[category][object]['Metadata']
                    contents = ' '.join(metadata['name'])
                    contents += ' '.join(metadata['description'])
                    contents += ' '.join(metadata['url'])
                    if all(term in contents.lower() for term in params):
                        response[category][object] = cache[category][object]
            response['count'] = sum(len(response[item]) for item in response)
    except Exception as e:
        response = {
            'name': 'Python Error',
            'description': str(type(e))+': '+str(e),
        }
    finally:
        return response


def loadCache(options):
    cachefile = pathlib.Path(options.cachefile)
    if options.verbose:
        logging.info('Loading cache ' + cache.name + '...')
    try:
        with open(cachefile, 'r') as cache:
            return json.loads(cache.read())
    except (ValueError, FileNotFoundError):
        if options.verbose:
            logging.error('Error loading the cachefile ' + cachefile.name)


def GenerateMatrix(options):
    merged = collections.defaultdict(lambda: dict())
    for category in categories:
        merged[category] = {}
        merged[category]['UIDs'] = {}
    for matrix in Matrices:
        matrixfile = pathlib.Path(options.cachedir+'/'+Matrices[matrix]['file'])
        if not matrixfile.exists():
            # Missing ATT&CK matrix file
            continue
        matrixname = Matrices[matrix]['name']
        matrixdescription = Matrices[matrix]['description']
        matrixurl = Matrices[matrix]['url']
        merged['Matrices'][matrix] = {'Metadata': {
                'name': [matrixname],
                'description': [matrixdescription],
                'url': [matrixurl],
        }}
        with open(matrixfile, 'r') as f:
            objects = json.loads(f.read())['objects']
            try:
                # Create all objects
                for object in objects:
                    if object['type'] in typemap:
                        type = typemap[object['type']]
                        objectnames = []
                        objectdescriptions = []
                        objecturls = []
                        objectmetadata = {
                            'names': objectnames,
                            'descriptions': objectdescriptions,
                            'urls': objecturls,
                        }
                        uid = object['id']
                        mitreid = None
                        revoked = False
                        deprecated = False
                        if 'description' in object:
                            objectdescriptions.append(object['description'])
                        if 'revoked' in object:
                            revoked = object['revoked']
                        if 'x_mitre_deprecated' in object:
                            deprecated = object['x_mitre_deprecated']
                        if 'external_references' in object:
                            for external_reference in object['external_references']:
                                if 'external_id' in external_reference:
                                    if 'mitre' in external_reference['source_name']:
                                        mitreid = external_reference['external_id']
                                        if 'name' in object:
                                            objectnames.append(object['name'])
                                        if 'aliases' in object:
                                            for alias in object['aliases']:
                                                if alias not in objectnames:
                                                    objectnames.append(alias)
                                        if 'description' in object:
                                            if object['description'] not in objectdescriptions:
                                                objectdescriptions.append(object['description'])
                                        if 'url' in external_reference:
                                            objecturls.append(external_reference['url'])
                        if revoked:
                            objectdescriptions.append('Note: This MITRE ID has been **revoked** and should no longer be used.\n')
                        if deprecated:
                            objectdescriptions.append('Note: This MITRE ID has been **deprecated** and should no longer be used.\n')
                        if not mitreid in merged[type]:
                            merged[type][mitreid] = {}
                        merged[type][mitreid]['Metadata'] = {
                            'name': objectnames,
                            'description': objectdescriptions,
                            'url': objecturls,
                        }
                        # Add the matrix to the ID
                        if 'Matrices' not in merged[type][mitreid]:
                            merged[type][mitreid]['Matrices'] = {}
                            if not matrix in merged[type][mitreid]['Matrices']:
                                merged[type][mitreid]['Matrices'][matrix] = merged['Matrices'][matrix]['Metadata']
                        # Add the UID to the list
                        merged[type]['UIDs'][uid] = mitreid
            except:
                print("Failed to parse a JSON object:")
                pprint.pprint(object)
                raise
    for matrix in Matrices:
        matrixfile = pathlib.Path(options.cachedir+'/'+Matrices[matrix]['file'])
        if not matrixfile.exists():
            # Missing ATT&CK matrix file
            continue
        with open(matrixfile, 'r') as f:
            objects = json.loads(f.read())['objects']
        try:
            # Create all relationships
            for object in objects:
                if not object['type'] in typemap:
                    type = object['type']
                    if type == 'relationship':
                        try:
                            sourceuid = object['source_ref']
                            sourcemitretype = sourceuid.split('--')[0]
                            targetuid = object['target_ref']
                            targetmitretype = targetuid.split('--')[0]
                            if sourcemitretype in typemap and targetmitretype in typemap:
                                sourcetype = typemap[sourcemitretype]
                                sourcemitreid = merged[sourcetype]['UIDs'][sourceuid]
                                source = merged[sourcetype][sourcemitreid]
                                targettype = typemap[targetmitretype]
                                targetmitreid = merged[targettype]['UIDs'][targetuid]
                                target = merged[targettype][targetmitreid]
                                if not targettype in source:
                                    source[targettype] = {}
                                source[targettype][targetmitreid] = target['Metadata']
                                if not sourcetype in target:
                                    target[sourcetype] = {}
                                target[sourcetype][sourcemitreid] = source['Metadata']
                        except KeyError:
                            print("Failed to build a relationship between:")
                            #print(sourcetype+'/'+sourcemitreid,'->',targettype+'/'+targetmitreid)
                            print(sourcemitreid)
                            pprint.pprint(source)
                            print(targetmitreid)
                            pprint.pprint(target)
                            raise
        except:
            print("Failed to parse JSON object:")
            pprint.pprint(object)
            raise
    for category in categories:
        del merged[category]['UIDs']
    return merged

def DownloadMatrices(options):
    for matrix in Matrices:
        file, url = options.cachedir+'/'+Matrices[matrix]['file'], Matrices[matrix]['url']
        jsonfile = pathlib.Path(file)
        if not jsonfile.exists() or options.force:
            try:
                logging.info('Downloading ' + url)
                with urllib.request.urlopen(url) as response, open(jsonfile, 'wb') as outfile:
                    shutil.copyfileobj(response, outfile)
            except urllib.error.HTTPError as e:
                logging.error('Download of ' + url + ' failed: ' + e.reason)


if __name__ == "__main__":
    '''
    Interactive run from the command-line
    '''
    parser = argparse.ArgumentParser(description='MITRE ATT&CK® Matrix parser'
                                                 ' - can be run directly to '
                                                 'provide an API or imported '
                                                 'as a module to provide a '
                                                 'Python dictionary.')
    parser.add_argument('-f', '--force',
                        dest='force',
                        action='store_true',
                        default=options.force,
                        help='[optional] Redownload the matrices and overwrite '
                             'the cache file (clean run).')
    parser.add_argument('-d', '--daemonize',
                        dest='daemonize',
                        action='store_true',
                        default=False,
                        help='[optional] Daemonize and provide an API that '
                              'can be queried via webclients to return matrix '
                              'data (see docs).')
    parser.add_argument('-i', '--ip',
                        dest='ip',
                        default=options.ip,
                        required=False,
                        help='[optional] Host the daemon should listen '
                             'on (default: ' + options.ip + ').')
    parser.add_argument('-p', '--port',
                        dest='port',
                        default=options.port,
                        required=False,
                        help='[optional] Port the daemon should listen '
                             'on (default: ' + str(options.port) + ').')
    parser.add_argument('-k', '--key',
                        dest='token',
                        default=options.token,
                        required=False,
                        help='[optional] Block all web access unless a '
                             'valid token is offered (default: ' +
                             str(options.token) + ').')
    parser.add_argument('-v', '--verbose',
                        dest='verbose',
                        action='store_true',
                        default=options.verbose,
                        help='[optional] Print lots of debugging and verbose '
                             'information about what\'s happening (default: '
                             'disabled).')
    parser.add_argument('-l', '--logfile',
                        dest='logfile',
                        default=options.logfile,
                        help='[optional] Logfile for log output (default: \'' +
                             options.logfile + '\')')
    parser.add_argument('-m', '--cachedir',
                        dest='cachedir',
                        default=options.cachedir,
                        help='[optional] Directory for cache (default: \'' +
                             options.cachedir + '\')')
    parser.add_argument('-c', '--cachefile',
                        dest='cachefile',
                        default=options.cachefile,
                        help='[optional] Filename for cache (default: \'' +
                             options.cachefile + '\')')
    options = parser.parse_args()
    logging.basicConfig(filename=options.logfile, level=logging.INFO)
    cachefile = pathlib.Path(options.cachefile)
    if options.force:
        if options.verbose:
            logging.info('Generating the cachefile: ' + cachefile.name)
        DownloadMatrices(options)
        cache = GenerateMatrix(options)
        with open(cachefile, 'w') as cachefile:
            json.dump(cache, cachefile)
    if not options.daemonize:
        parser.print_help()
    else:
        if not cachefile.exists():
            if options.verbose:
                logging.info('Loading the cachefile: ' + cachefile.name)
            DownloadMatrices(options)
            cache = GenerateMatrix(options)
            with open(cachefile, 'w') as cachefile:
                json.dump(cache, cachefile)
        else:
            with open(cachefile, 'r') as cachefile:
                cache = json.load(cachefile)
        try:
            port = int(options.port)
        except ValueError:
            logging.error('The listening port must be a numeric value')
        uvicorn.run('attackmatrix:app', host=options.ip, port=options.port, log_level='info', reload=True)
else:
    '''
    Module import: GenerateMatrix() to get a Python dict
    '''
