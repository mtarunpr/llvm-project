#include "X86.h"
#include "X86InstrInfo.h"
#include "llvm/CodeGen/MachineFunctionPass.h"
#include "llvm/CodeGen/MachineInstrBuilder.h"
#include "llvm/CodeGen/TargetRegisterInfo.h"
#include "llvm/MC/MCAsmInfo.h"
#include "llvm/MC/MCContext.h"
#include "llvm/MC/MCInstPrinter.h"
#include "llvm/MC/MCInstrInfo.h"
#include "llvm/MC/MCRegisterInfo.h"
#include "llvm/MC/MCStreamer.h"
#include "llvm/MC/MCSubtargetInfo.h"

using namespace llvm;

#define X86_MACHINEINSTR_PRINTER_PASS_NAME "Dummy X86 machineinstr printer pass"

unsigned long hash(char *str) {
  unsigned long hash = 5381;
  int c;

  while ((c = *str++))
    hash = ((hash << 5) + hash) + c; /* hash * 33 + c */

  return hash;
}

namespace {

class X86MachineInstrPrinter : public MachineFunctionPass {
public:
  static char ID;

  X86MachineInstrPrinter() : MachineFunctionPass(ID) {
    initializeX86MachineInstrPrinterPass(*PassRegistry::getPassRegistry());
  }

  bool runOnMachineFunction(MachineFunction &MF) override;

  StringRef getPassName() const override {
    return X86_MACHINEINSTR_PRINTER_PASS_NAME;
  }
};

char X86MachineInstrPrinter::ID = 0;

bool X86MachineInstrPrinter::runOnMachineFunction(MachineFunction &MF) {
  const TargetInstrInfo *TII = MF.getSubtarget().getInstrInfo();

  for (auto &MBB : MF) {
    outs() << "Basic block: " << MBB << "\n";

    for (auto &MI : MBB) {
      if (MI.isBranch() || MI.isCall()) {
        outs() << "Machine instruction: " << MI << "\n";

        std::string str;
        raw_string_ostream rso(str);
        rso << MI.getOperand(0).getMBB()->getFullName() << MI.getOperand(0);
        rso.flush();

        // movq $ID, %rax
        BuildMI(MBB, &MI, MI.getDebugLoc(), TII->get(X86::MOV64ri), X86::RAX)
            .addImm(hash((char *)str.c_str()));

        // Concatenate MF.getName() with MI.getOperand(0)
        outs() << "TO BE HASHED NAME: " << str.c_str() << "\n";

        // movq %rax, %xmm1
        BuildMI(MBB, &MI, MI.getDebugLoc(), TII->get(X86::MOV64rr), X86::XMM1)
            .addReg(X86::RAX);

        // Insert aesenc %xmm0, %xmm1
        // BuildMI(MBB, &MI, MI.getDebugLoc(),
        // TII->get(X86::AESENCrr)).addReg(X86::XMM0).addReg(X86::XMM1);

        // aesenc %xmm0, %xmm1
        BuildMI(MBB, &MI, MI.getDebugLoc(), TII->get(X86::INLINEASM))
            .addExternalSymbol("aesenc %xmm0, %xmm1");

        // movd %xmm1, %eax
        BuildMI(MBB, &MI, MI.getDebugLoc(), TII->get(X86::INLINEASM))
            .addExternalSymbol("movd %xmm1, %eax");
        // BuildMI(MBB, &MI, MI.getDebugLoc(), TII->get(X86::MOV32rr),
        // X86::EAX).addReg(X86::XMM1);

        // Insert new instruction that does the same as MI but jumps to *%rax
        // instead of MI's target
        // TODO: need to map from MI.getOpcode() to the correspoding jump
        // instruction that uses register instead of immediate value

        if (MI.isCall()) {
          BuildMI(MBB, &MI, MI.getDebugLoc(), TII->get(X86::CALL64r))
              .addReg(X86::RAX);
        } else if (MI.isConditionalBranch()) {
          std::string str;

          switch (MI.getOperand(1).getImm()) {
          case X86::COND_O:
            str = "jo";
            break;
          case X86::COND_NO:
            str = "jno";
            break;
          case X86::COND_B:
            str = "jb";
            break;
          case X86::COND_AE:
            str = "jae";
            break;
          case X86::COND_E:
            str = "je";
            break;
          case X86::COND_NE:
            str = "jne";
            break;
          case X86::COND_BE:
            str = "jbe";
            break;
          case X86::COND_A:
            str = "ja";
            break;
          case X86::COND_S:
            str = "js";
            break;
          case X86::COND_NS:
            str = "jns";
            break;
          case X86::COND_P:
            str = "jp";
            break;
          case X86::COND_NP:
            str = "jnp";
            break;
          case X86::COND_L:
            str = "jl";
            break;
          case X86::COND_GE:
            str = "jge";
            break;
          case X86::COND_LE:
            str = "jle";
            break;
          case X86::COND_G:
            str = "jg";
            break;
          }

          str += " rax";

          // TODO: passing str here doesn't work, may need to copy-paste BuildMI
          // in each switch case. Additionally, jne *%rax doesn't work, so need
          // to figure that out
          // BuildMI(MBB, &MI, MI.getDebugLoc(), TII->get(X86::INLINEASM))
          //     .addExternalSymbol("jne rax");
        } else {
          BuildMI(MBB, &MI, MI.getDebugLoc(), TII->get(X86::JMP32r))
              .addReg(X86::EAX);
        }

        // Remove original MI
        // MBB.erase_instr(&MI);
      }
    }

    outs() << "Basic block after: " << MBB << "\n";
  }
  return true;
}

} // end of anonymous namespace

INITIALIZE_PASS(X86MachineInstrPrinter, "x86-machineinstr-printer",
                X86_MACHINEINSTR_PRINTER_PASS_NAME,
                false, // is CFG only?
                false  // is analysis?
)

FunctionPass *llvm::createX86MachineInstrPrinter() {
  return new X86MachineInstrPrinter();
}
