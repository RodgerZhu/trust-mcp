#!/usr/bin/env python3

import os
import sys
import time

# load build module 
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from quote_appraisal import (
        verify_quote_qvt,
        appraise_verification_token,
        authenticate_appraisal_result,
        authenticate_policy_owner,
        check_quote_type,
        ecdsa_quote_verify,
        SGX_QUOTE_TYPE,
        TDX_QUOTE_TYPE,
        AUTH_SUCCESS,
        AUTH_FAILURE,
        QuoteVerifyError,
    )
    print("✓ successfully load quote_appraisal modules")
except ImportError as e:
    print(f"✗ load error: {e}")
    print("please confirm the module is built : python setup.py build_ext --inplace")
    sys.exit(1)


def read_file(filepath):
    try:
        with open(filepath, 'rb') as f:
            return f.read()
    except FileNotFoundError:
        print(f"✗ file not find: {filepath}")
        return None
    except Exception as e:
        print(f"✗ read error: {e}")
        return None


def read_text_file(filepath):
    data = read_file(filepath)
    if data is not None and not data.endswith(b'\x00'):
        data = data + b'\x00'
    return data


def test_check_quote_type(quote_data):
    print("\n=== test: check_quote_type ===")
    
    quote_type = check_quote_type(quote_data)
    
    if quote_type == SGX_QUOTE_TYPE:
        print("✓ Quote type: SGX")
        return "SGX"
    elif quote_type == TDX_QUOTE_TYPE:
        print("✓ Quote type: TDX")
        return "TDX"
    else:
        print(f"✗ unknown Quote type: {quote_type}")
        return None


def test_verify_quote_qvt(quote_data):
    print("\n=== test: verify_quote_qvt ===")
    
    try:
        start = time.time()
        jwt_token = verify_quote_qvt(quote_data)
        elapsed = time.time() - start
        
        print(f"✓ Quote verified succes")
        print(f"  JWT token size: {len(jwt_token)} bytes")
        
        jwt_preview = jwt_token[:100].decode('utf-8', errors='replace')
        print(f"  JWT preview: {jwt_preview}...")
        
        return jwt_token
        
    except QuoteVerifyError as e:
        print(f"✗ Quote verified failed: {e}")
        return None


def test_appraise_verification_token(jwt_token, tenant_policy, platform_policy):
    print("\n=== test: appraise_verification_token ===")
    
    try:
        policies = [tenant_policy, platform_policy]
        
        start = time.time()
        appraisal_result = appraise_verification_token(jwt_token, policies)
        elapsed = time.time() - start
        
        print(f"✓ appraisal success")
        print(f"  appraisal_result size: {len(appraisal_result)} bytes")
        
        return appraisal_result
        
    except QuoteVerifyError as e:
        print(f"✗ appraisal failed: {e}")
        return None
    except ValueError as e:
        print(f"✗ parameter error: {e}")
        return None


def test_authenticate_appraisal_result(appraisal_result, tenant_policy, platform_policy):
    print("\n=== test: authenticate_appraisal_result ===")
    
    try:
        result = authenticate_appraisal_result(
            appraisal_result, 
            tenant_policy, 
            platform_policy
        )
        
        if result == AUTH_SUCCESS:
            print(f"✓ auth policy success (result: {result})")
        elif result == AUTH_FAILURE:
            print(f"✗ auth policy failed (result: {result})")
        else:
            print(f" ⚠ auth polcy incomplete (result: {result})")
        
        return result
        
    except QuoteVerifyError as e:
        print(f"✗ verify error: {e}")
        return None


def test_authenticate_policy_owner(quote_data, appraisal_result, pub_key):
    print("\n=== test: authenticate_policy_owner ===")
    
    try:
        keys = [pub_key]
        
        result = authenticate_policy_owner(
            quote_data,
            appraisal_result,
            keys
        )
        
        if result == AUTH_SUCCESS:
            print(f"✓ policy owner auth success (result: {result})")
        else:
            print(f"✗ policy owner auth error (result: {result})")
        
        return result
        
    except QuoteVerifyError as e:
        print(f"✗ verify error: {e}")
        return None


def test_ecdsa_quote_verify(quote_data, tenant_policy, platform_policy, pub_key):

    try:
        result = ecdsa_quote_verify(
            quote_data,
            tenant_policy,
            platform_policy,
            [pub_key],
            verbose=True
        )
        
        print(f"Quote type: {result.get('quote_type', 'N/A')}")
        print(f"verify success: {result.get('verify_success', False)}")
        print(f"appraisal success: {result.get('appraisal_success', False)}")
        print(f"policy auth success: {result.get('auth_success', False)}")
        print(f"policy owner auth success: {result.get('owner_auth_success', False)}")
        print(f"overall success: {result.get('overall_success', False)}")
        
        if result.get('error'):
            print(f"error message: {result['error']}")
        
        return result
        
    except Exception as e:
        print(f"✗ overall testing error: {e}")
        import traceback
        traceback.print_exc()
        return None


def run_individual_tests(quote_data, tenant_policy, platform_policy, pub_key):
    
    # 1. check Quote type
    quote_type = test_check_quote_type(quote_data)
    
    # 2. verify Quote
    jwt_token = test_verify_quote_qvt(quote_data)
    if jwt_token is None:
        print("\n✗ Quote verify failed, stop testing")
        return False
    
    # 3. appraisal verifition result
    appraisal_result = test_appraise_verification_token(
        jwt_token, 
        tenant_policy, 
        platform_policy
    )
    if appraisal_result is None:
        print("\n✗ appraisal failed stop testing")
        return False
    
    # 4. auth appraisal result
    auth_result = test_authenticate_appraisal_result(
        appraisal_result,
        tenant_policy,
        platform_policy
    )
    
    # 5. auth policy owner
    owner_result = test_authenticate_policy_owner(
        quote_data,
        appraisal_result,
        pub_key
    )

    
    return True


def run_full_test(quote_data, tenant_policy, platform_policy, pub_key):
    
    result = test_ecdsa_quote_verify(
        quote_data,
        tenant_policy,
        platform_policy,
        pub_key
    )
    
    return result


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='TDX/SGX Quote Appraisal testing')
    parser.add_argument('-q', '--quote', default='../../QuoteGenerationSample/quote.dat',
                       help='Quote file path (default: ../../QuoteGenerationSample/quote.dat)')
    parser.add_argument('-t', '--tenant', default='../Policies/sgx_enclave_policy.jwt',
                       help='tenant policy path')
    parser.add_argument('-p', '--platform', default='../Policies/sgx_platform_policy_strict.jwt',
                       help='platform policy path')
    parser.add_argument('-k', '--pubkey', default='../Policies/ec_pub.pem',
                       help='public key path')
    parser.add_argument('--full-only', action='store_true',
                       help='full procedure')
    parser.add_argument('--individual-only', action='store_true',
                       help='module test')
    
    args = parser.parse_args()
    
    print("="*60)
    print("TDX/SGX Quote Appraisal test")
    print("="*60)

    quote_data = read_file(args.quote)
    tenant_policy = read_text_file(args.tenant)
    platform_policy = read_text_file(args.platform)
    pub_key = read_text_file(args.pubkey)
    
    if quote_data is None:
        print("\n✗ cannot load Quote file")
        return 1
    
    if tenant_policy is None or platform_policy is None:
        print("\n✗ cannot load policy file")
        return 1
    
    if pub_key is None:
        print("\n✗ cannot load public key")
        return 1
    
    print(f"  quote size: {len(quote_data)} bytes")
    print(f"  tenant-policy: {len(tenant_policy)} bytes")
    print(f"  patform-policy: {len(platform_policy)} bytes")
    print(f"  public-key: {len(pub_key)} bytes")
    
    success = True
    
    if not args.full_only:
        success = run_individual_tests(
            quote_data, 
            tenant_policy, 
            platform_policy, 
            pub_key
        ) and success
    
    if not args.individual_only:
        result = run_full_test(
            quote_data,
            tenant_policy,
            platform_policy,
            pub_key
        )
        success = success and (result is not None and result.get('overall_success', False))
    
    print("\n" + "="*60)
    if success:
        print("✓ all test pass")
    else:
        print("✗ part test failer")
    print("="*60)
    
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
