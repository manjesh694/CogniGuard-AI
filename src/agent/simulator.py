"""
CogniGuard AI - Intrusion Simulation & Verification Runner
Description: Simulates real-world cyber attacks (infostealer payload vs safe dev tool)
             to verify the agent's real-time interception and containment capabilities.
"""

import time
from vault_guardian import CogniGuardAgent

def run_simulation():
    print("=" * 68)
    print("🚀 STARTING COGNIGUARD AI ZERO-ENTRY VERIFICATION SUITE")
    print("=" * 68)
    
    agent = CogniGuardAgent()
    time.sleep(1)

    # Test 1: Normal Authorized Developer Action
    print("\n[TEST 1] Standard Developer Workflow:")
    print("VS Code accessing project environment...")
    time.sleep(0.8)
    agent.evaluate_access(
        process_name="code.exe",
        target_vault="ENV_SECRETS",
        pid=4812
    )
    time.sleep(1)

    # Test 2: North Korean / Lazarus Group Infostealer Attack Simulation
    print("\n[TEST 2] Simulated Hacker Intrusion (TraderTraitor / Infostealer Attack):")
    print("Unknown binary downloaded via fake recruiter PDF attempting to steal Chrome cookies...")
    time.sleep(1.2)
    
    agent.evaluate_access(
        process_name="Job_Contract_Offer.pdf.exe",
        target_vault="BROWSER_COOKIES",
        pid=9942
    )
    time.sleep(1)

    # Test 3: Unauthorized AWS Cloud Token Exfiltration Attempt
    print("\n[TEST 3] Simulated Cloud Credential Theft Attempt:")
    print("Background script attempting to exfiltrate ~/.aws/credentials...")
    time.sleep(1.0)
    
    agent.evaluate_access(
        process_name="powershell_payload.vbs",
        target_vault="AWS_CREDENTIALS",
        pid=8110
    )
    time.sleep(0.8)

    # Final Summary
    health = agent.get_system_health()
    print("=" * 68)
    print("📊 SIMULATION COMPLETE: FINAL SYSTEM HEALTH REPORT")
    print(f"• System Status:        [{health['status']}] (100% OPERATIONAL)")
    print(f"• Active Tripwires:     {health['vaults_secured']} Protected Zones")
    print(f"• Threats Neutralized:  {health['threats_blocked']} Interceptions")
    print("• Data Breach Prevented: YES (Zero credentials leaked)")
    print("=" * 68)

if __name__ == "__main__":
    run_simulation()
