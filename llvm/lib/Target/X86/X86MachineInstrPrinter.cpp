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

/**
 * @brief Inserts hash calculation instructions before MI.
 *
 * @param MI Jump/call instruction before which to insert hash calculation
 * @param MIJump Jump instruction whose target is to be replaced with *%rax
 * @param MBB Machine basic block containing MI
 * @param TII Target instruction info
 */
void insertHashInstructions(MachineInstr &MI, MachineBasicBlock &MBB,
                            const TargetInstrInfo *TII) {

  // TODO: can we directly use += instead of stream?
  std::string MBBLabel;
  raw_string_ostream MBBLabelOstream(MBBLabel);
  MBBLabelOstream << MI.getOperand(0).getMBB()->getFullName()
                  << MI.getOperand(0);
  MBBLabelOstream.flush();

  // movq $ID, %rax
  BuildMI(MBB, &MI, MI.getDebugLoc(), TII->get(X86::MOV64ri), X86::RAX)
      .addImm(hash((char *)MBBLabel.c_str()));

  // Concatenate MF.getName() with MI.getOperand(0)
  outs() << "TO BE HASHED NAME: " << MBBLabel.c_str() << "\n";

  // movq %rax, %xmm1
  BuildMI(MBB, &MI, MI.getDebugLoc(), TII->get(X86::MOV64rr), X86::XMM1)
      .addReg(X86::RAX);

  // aesenc %xmm0, %xmm1
  BuildMI(MBB, &MI, MI.getDebugLoc(), TII->get(X86::INLINEASM))
      .addExternalSymbol("aesenc %xmm0, %xmm1");

  // movd %xmm1, %eax
  BuildMI(MBB, &MI, MI.getDebugLoc(), TII->get(X86::INLINEASM))
      .addExternalSymbol("movd %xmm1, %eax");
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

  // Do a first pass to find all basic blocks that don't end with a jump or
  // return and insert a jump to the next basic block
  for (auto &MBB : MF) {
    if (!MBB.empty()) {
      MachineInstr &MI = MBB.back();
      if (!MI.isBranch() && !MI.isReturn()) {
        // Insert jump to next basic block
        MachineBasicBlock *NextMBB = &*std::next(MBB.getIterator());
        BuildMI(MBB, MBB.end(), MI.getDebugLoc(), TII->get(X86::JMP_1))
            .addMBB(NextMBB);
      }
    }
  }

  std::vector<MachineInstr *> toRemove;

  for (auto &MBB : MF) {
    outs() << "Basic block: " << MBB << "\n";

    for (auto &MI : MBB) {
      outs() << "Machine instruction: " << MI << "\n";

      if (MI.isBranch() || MI.isCall()) {
        if (MI.isCall()) {
          insertHashInstructions(MI, MBB, TII);
          BuildMI(MBB, &MI, MI.getDebugLoc(), TII->get(X86::CALL32r))
              .addReg(X86::RAX);
          toRemove.push_back(&MI);
        } else if (MI.isConditionalBranch()) {
          // Get the next basic block
          MachineBasicBlock *NextMBB = &*std::next(MBB.getIterator());

          // Create a new basic block for the JCC to jump to
          MachineBasicBlock *NewMBB = MF.CreateMachineBasicBlock();
          // Find the iterator pointing to the current basic block
          MachineFunction::iterator It = MF.begin();
          for (; It != MF.end(); ++It) {
            if (&*It == &MBB)
              break;
          }
          MF.insert(++It, NewMBB);
          MBB.addSuccessor(NewMBB);
          NewMBB->addSuccessor(NextMBB);

          // Insert jump to the next basic block in the original (unmodified)
          // code
          BuildMI(MBB, MBB.end(), MI.getDebugLoc(), TII->get(X86::JMP_1))
              .addMBB(NextMBB);

          // In NewMBB, Insert jump to the original target
          BuildMI(*NewMBB, NewMBB->end(), MI.getDebugLoc(),
                  TII->get(X86::JMP_1))
              .addMBB(MI.getOperand(0).getMBB());

          // Modify MI to conditionally jump to NewMBB
          MI.getOperand(0).setMBB(NewMBB);
        } else if (MI.isUnconditionalBranch()) {
          insertHashInstructions(MI, MBB, TII);
          BuildMI(MBB, &MI, MI.getDebugLoc(), TII->get(X86::JMP32r))
              .addReg(X86::EAX);
          toRemove.push_back(&MI);
        }
      }
    }

    outs() << "Basic block after: " << MBB << "\n";
  }

  while (!toRemove.empty()) {
    MachineInstr *MI = toRemove.back();
    toRemove.pop_back();
    MI->eraseFromBundle();
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
