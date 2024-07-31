
# 1. Test Buisness Logic Data Validation

- Looking for data entry points or hand off points between systems or software

- Once found try to insert logically invalid data into the application/system.

# 2. Test ability to Forge Request

- Looking for guessable predictable or hidden functionality of Fields

- Once foundtry to insert logically valid data into the application/system allowing the user go through the application/system against the normal business logic workflow

# 3. Test Integrity Checks

- Looking for parts of the application/system (components ie for example input feilds, database or logs) that move, store or handle data/information

- For each identified component determine what type of data/information is logically acceptable and what types of defence should gaurd against, also consider who according to business logic is allowed to insert, update and delete data/info

- Attempt to insert, update or edit delete the data/information values with invalid data/information into each component (ie input, database or log) by users that should not be allowed as per the buisness logic workflow

# 4. Test for Process Timing

- Looking for application/system functionality that may be impacted by time, such as execution time or actions that help users predict a failure outcome or allow one to circumvent any part of business

# 5. Test Number of Times a Function can be Used Limits

- Looking for function or features in the application or system that should not be executed more than that a single time during business logic workflow

# 6. Testing for Cirumvention of workflow

- looking for methods to skip or go to steps in the application process in a diffrent order from the designed/intended buisness logic flow

# 7. Test Upload of Unexptected File Typs

- Review the project documentation and perform some exploratory testing for file type that should be unsuppoerted by application

- Try to upload unsupported file types and verify that it are properly rejected

- If multiple files can be uploaded at once there must be tests in place to verify that each file is properly executed

# 8. Test Upload of Malicious Files

- Develop or acquire a known 'malicious' file

- Try to upload malicious file to the application system and verify that it is correclty rejected

- If multiple files can be uploaded at once there must be tests in place to verify that each file is properly executed