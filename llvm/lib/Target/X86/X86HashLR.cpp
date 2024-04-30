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
#include <set>

using namespace llvm;

#define X86_HASHLR_PASS_NAME "X86 HashLR Pass"

/**
 * @brief Hash function for strings.
 *
 * @param str String to hash
 * @return Hash value
 */
unsigned long hash(const char *str) {
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
 * @param MIJump Jump instruction whose target is to be replaced with *%r10
 * @param MBB Machine basic block containing MI
 * @param TII Target instruction info
 */
void insertHashInstructions(MachineInstr &MI, MachineBasicBlock &MBB,
                            const TargetInstrInfo *TII) {

  std::string MBBLabel;
  raw_string_ostream MBBLabelOstream(MBBLabel);
  MBBLabelOstream << MI.getOperand(0).getMBB()->getFullName()
                  << MI.getOperand(0);
  MBBLabelOstream.flush();

  // If the label contains a '@', it's a function name and we
  // want to hash the name of the first basic block in it instead
  if (MBBLabel.find('@') != std::string::npos) {
    MBBLabel = MBBLabel.substr(1);
    MBBLabel.append(":%bb.0");
  }

  // movq $ID, %r10
  BuildMI(MBB, &MI, MI.getDebugLoc(), TII->get(X86::MOV64ri), X86::R10)
      .addImm(hash(MBBLabel.c_str()));

  // movq %r10, %xmm1
  BuildMI(MBB, &MI, MI.getDebugLoc(), TII->get(X86::MOV64rr), X86::XMM1)
      .addReg(X86::R10);

  // aesenc %xmm7, %xmm1
  BuildMI(MBB, &MI, MI.getDebugLoc(), TII->get(X86::INLINEASM))
      .addExternalSymbol("aesenc %xmm7, %xmm1");

  // movd %xmm1, %r10
  BuildMI(MBB, &MI, MI.getDebugLoc(), TII->get(X86::INLINEASM))
      .addExternalSymbol("movd %xmm1, %r10");
}

namespace {

class X86HashLR : public MachineFunctionPass {
public:
  static char ID;

  X86HashLR() : MachineFunctionPass(ID) {
    initializeX86HashLRPass(*PassRegistry::getPassRegistry());
  }

  bool runOnMachineFunction(MachineFunction &MF) override;

  StringRef getPassName() const override { return X86_HASHLR_PASS_NAME; }
};

char X86HashLR::ID = 0;

bool X86HashLR::runOnMachineFunction(MachineFunction &MF) {
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
  std::set<MachineBasicBlock *> leaveAsContiguous;

  for (auto &MBB : MF) {
    for (auto &MI : MBB) {
      if (MI.isBranch() || MI.isCall()) {
        if (MI.isCall()) {
          insertHashInstructions(MI, MBB, TII);
          BuildMI(MBB, &MI, MI.getDebugLoc(), TII->get(X86::CALL64r))
              .addReg(X86::R10);
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
          leaveAsContiguous.insert(NewMBB);

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
          BuildMI(MBB, &MI, MI.getDebugLoc(), TII->get(X86::JMP64r))
              .addReg(X86::R10);
          toRemove.push_back(&MI);
        }
      }
    }
  }

  while (!toRemove.empty()) {
    MachineInstr *MI = toRemove.back();
    toRemove.pop_back();
    MI->eraseFromBundle();
  }

  // Do a final pass through all basic blocks to print their identifiers
  for (auto &MBB : MF) {
    if (leaveAsContiguous.find(&MBB) != leaveAsContiguous.end()) {
      continue;
    }

    // Write to ostream
    std::string MBBLabel;
    raw_string_ostream MBBLabelOstream(MBBLabel);
    MBBLabelOstream << MF.getName() << ":";
    MBB.printAsOperand(MBBLabelOstream, false);
    MBBLabelOstream << "\n";
    MBBLabelOstream.flush();

    // If label is main:%bb.0, also output "main"
    if (MBBLabel.find("main:%bb.0") != std::string::npos) {
      outs() << "main=";
    }

    outs() << hash(MBBLabel.c_str()) << "\n";
  }

  return true;
}

} // end of anonymous namespace

INITIALIZE_PASS(X86HashLR, "x86-hashlr", X86_HASHLR_PASS_NAME,
                false, // is CFG only?
                false  // is analysis?
)

FunctionPass *llvm::createX86HashLR() { return new X86HashLR(); }
