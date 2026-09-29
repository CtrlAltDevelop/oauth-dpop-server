// End-to-end interop: the published Dart DPoP client against this server.
//
//   dart run bin/interop.dart --issuer http://127.0.0.1:8000 \
//       --client-id ... --client-secret ...
//
// Every step asserts what RFC 9449 says should happen, and the program exits
// non-zero on the first surprise. Nothing here reimplements DPoP: proofs,
// thumbprints and headers all come from package:dpop_client.
import 'dart:convert';
import 'dart:io';

import 'package:dpop_client/dpop_client.dart';
import 'package:http/http.dart' as http;

late final Uri issuer;
late final String clientId;
late final String clientSecret;

int _step = 0;

void check(bool condition, String what) {
  _step++;
  if (!condition) {
    stderr.writeln('FAIL  $_step. $what');
    exit(1);
  }
  stdout.writeln('ok    $_step. $what');
}

Map<String, dynamic> jsonOf(http.Response response) =>
    jsonDecode(response.body) as Map<String, dynamic>;

Map<String, dynamic> claimsOf(String jwt) =>
    jsonDecode(
          utf8.decode(base64Url.decode(base64Url.normalize(jwt.split('.')[1]))),
        )
        as Map<String, dynamic>;

String basic() =>
    'Basic ${base64.encode(utf8.encode('$clientId:$clientSecret'))}';

void parseArgs(List<String> args) {
  final values = <String, String>{};
  for (var i = 0; i + 1 < args.length; i += 2) {
    values[args[i].replaceFirst('--', '')] = args[i + 1];
  }
  for (final name in ['issuer', 'client-id', 'client-secret']) {
    if (!values.containsKey(name)) {
      stderr.writeln(
        'usage: interop.dart --issuer URL --client-id ID '
        '--client-secret SECRET',
      );
      exit(64);
    }
  }
  issuer = Uri.parse(values['issuer']!);
  clientId = values['client-id']!;
  clientSecret = values['client-secret']!;
}

Future<http.Response> tokenRequest(
  DPoPClient client,
  Uri endpoint, {
  String? nonce,
}) {
  final proof = client.createProof(url: endpoint, method: 'POST', nonce: nonce);
  return http.post(
    endpoint,
    headers: {...proof.headers(), 'Authorization': basic()},
    body: {
      'grant_type': 'client_credentials',
      'scope': 'orders:read orders:write',
    },
  );
}

Future<void> main(List<String> args) async {
  parseArgs(args);

  // Discovery (RFC 8414).
  final metadataResponse = await http.get(
    issuer.replace(path: '/.well-known/oauth-authorization-server'),
  );
  check(metadataResponse.statusCode == 200, 'metadata is served');
  final metadata = jsonOf(metadataResponse);
  check(metadata['issuer'] == issuer.toString(), 'metadata issuer matches');
  check(
    (metadata['dpop_signing_alg_values_supported'] as List).contains('ES256'),
    'server accepts ES256 proofs, the one dpop_client signs',
  );
  final tokenEndpoint = Uri.parse(metadata['token_endpoint'] as String);

  final keyPair = DPoPKeyPair.generate();
  final client = DPoPClient(keyPair);

  // RFC 9449 §8: the first request has no nonce and is told to use one.
  final first = await tokenRequest(client, tokenEndpoint);
  check(
    first.statusCode == 400 && jsonOf(first)['error'] == 'use_dpop_nonce',
    'first token request is answered use_dpop_nonce',
  );
  final nonce = first.headers['dpop-nonce'];
  check(nonce != null && nonce.isNotEmpty, 'a DPoP-Nonce header comes with it');

  // Retry with the nonce, as the dpop_client README describes.
  final second = await tokenRequest(client, tokenEndpoint, nonce: nonce);
  check(second.statusCode == 200, 'retry with the nonce gets a token');
  final body = jsonOf(second);
  check(body['token_type'] == 'DPoP', 'token_type is DPoP (RFC 9449 §5)');
  final accessToken = body['access_token'] as String;
  final claims = claimsOf(accessToken);
  check(
    (claims['cnf'] as Map)['jkt'] == keyPair.thumbprint,
    'cnf.jkt equals the client key thumbprint (RFC 7638, both sides agree)',
  );

  // RFC 9449 §7: call the resource server with the bound token.
  final orders = issuer.replace(path: '/api/orders', query: 'limit=5');
  final getProof = client.createProof(
    url: orders,
    method: 'GET',
    accessToken: accessToken,
  );
  final listed = await http.get(orders, headers: getProof.headers());
  check(
    listed.statusCode == 200,
    'GET /api/orders with a proof carrying ath (htu drops the query)',
  );

  final placeProof = client.createProof(
    url: issuer.replace(path: '/api/orders'),
    method: 'POST',
    accessToken: accessToken,
  );
  final placed = await http.post(
    issuer.replace(path: '/api/orders'),
    headers: {...placeProof.headers(), 'Content-Type': 'application/json'},
    body: jsonEncode({'item': 'interop widget', 'quantity': 2}),
  );
  check(placed.statusCode == 201, 'POST /api/orders creates an order');

  // Negative checks against the live server.
  final replay = await http.get(orders, headers: getProof.headers());
  check(
    replay.statusCode == 401 &&
        (replay.headers['www-authenticate'] ?? '').contains(
          'invalid_dpop_proof',
        ),
    'replaying the same proof is refused (RFC 9449 §11.1)',
  );

  final bearer = await http.get(
    orders,
    headers: {
      'Authorization': 'Bearer $accessToken',
      'DPoP': client
          .createProof(url: orders, method: 'GET', accessToken: accessToken)
          .token,
    },
  );
  check(
    bearer.statusCode == 401 &&
        (bearer.headers['www-authenticate'] ?? '').contains('invalid_token'),
    'the bound token presented as Bearer is refused (RFC 9449 §7.2)',
  );

  final thief = DPoPClient(DPoPKeyPair.generate());
  final stolen = await http.get(
    orders,
    headers: thief
        .createProof(url: orders, method: 'GET', accessToken: accessToken)
        .headers(),
  );
  check(
    stolen.statusCode == 401,
    'the token with a proof from another key is refused',
  );

  stdout.writeln('\nall $_step interop checks passed');
}
