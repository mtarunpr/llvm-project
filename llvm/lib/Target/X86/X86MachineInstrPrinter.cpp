#include "X86.h"
#include "X86InstrInfo.h"
#include "llvm/CodeGen/MachineFunctionPass.h"
#include "llvm/CodeGen/MachineInstrBuilder.h"
#include "llvm/CodeGen/TargetRegisterInfo.h"

using namespace llvm;

#define X86_MACHINEINSTR_PRINTER_PASS_NAME "Dummy X86 machineinstr printer pass"

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
  const TargetRegisterInfo *TRI = MF.getSubtarget().getRegisterInfo();

  // Create constants and registers
  unsigned int RAX = TRI->getEncodingValue(X86::RAX);
  unsigned int XMM0 = TRI->getEncodingValue(X86::XMM0);
  unsigned int XMM1 = TRI->getEncodingValue(X86::XMM1);

  for (auto &MBB : MF) {
    outs() << "Basic block: " << MBB << "\n";

    for (auto &MI : MBB) {
      if (MI.isBranch()) {

        // Insert movq $42, %rax
        // Insert movq $42, %rax
        // TODO: Change 42 to actual index of basic block
        outs() << "Machine instruction: " << MI << "\n";
        BuildMI(MBB, &MI, MI.getDebugLoc(), TII->get(X86::NOOP));

        // // Insert movq %rax, %xmm1
        // BuildMI(MBB, MBB.end(), DebugLoc(),
        // TII->get(X86::MOV64rr)).addReg(RAX).addReg(XMM1);

        // // Insert aesenc %xmm0, %xmm1
        // BuildMI(MBB, MBB.end(), DebugLoc(),
        // TII->get(X86::AESENCrr)).addReg(XMM0).addReg(XMM1);

        // // Insert movd %xmm1, %eax
        // BuildMI(MBB, MBB.end(), DebugLoc(),
        // TII->get(X86::MOV64rr)).addReg(XMM1).addReg(RAX);

        // // Insert jmp *%rax
        // BuildMI(MBB, MBB.end(), DebugLoc(),
        // TII->get(X86::JMP64m)).addReg(RAX);
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
