# Define the main module
obj-m += network_shadow.o

# Define dependencies
network_shadow-objs := network_shadow.o ../recovery_evaluator/recovery_evaluator.o ../fault_injection/fault_injection.o

# Main build rule
all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) \
		M_RECOVERY_EVALUATOR=$(PWD)/../recovery_evaluator \
		M_FAULT_INJECTION=$(PWD)/../fault_injection \
		modules

# Clean rule
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	make -C $(PWD)/../recovery_evaluator clean
	make -C $(PWD)/../fault_injection clean

# Add dependencies
network_shadow.o: ../recovery_evaluator/recovery_evaluator.o ../fault_injection/fault_injection.o