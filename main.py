def show_menu():
    print("\n=== Secure User System ===")
    print("1. Register")
    print("2. Login")
    print("3. Exit")

while True:
    show_menu()
    choice = input("Select an option (1-3): ")

    if choice == "1":
        print(" Registering user...")
       
    elif choice == "2":
        print(" Logging in...")
     
    elif choice == "3":
        print(" Exiting. Bye!")
        break
    else:
        print(" Invalid choice. Please enter 1, 2 or 3.")