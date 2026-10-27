GAXIS-Lumen — Product Understanding Guide
1. What is GAXIS-Lumen?
GAXIS-Lumen is GREEN Limited's central company knowledge and controlled document access system.
Imagine GREEN has hundreds of company documents:
- HR policies and employee induction guides
- Engineering standards and technical procedures
- Health and safety procedures
- Quality management and ISO documents
- Environmental procedures
- Training videos and audio
Currently, these documents may be distributed through folders, email and other channels. Employees may have different versions, and management cannot reliably prove which version somebody read.
GAXIS-Lumen solves that problem.
It provides one controlled place where authorised people can find the current approved documents, read them and acknowledge mandatory material.
It also gives GREEN an audit history of which person opened and acknowledged which version.
2. Who uses the product?
Let's imagine four people working at GREEN.
Person	System responsibility	What they do
Admin	Administrator	Manages accounts and access
Sarah	Document Owner	Prepares HR documents
Michael	Document Releaser	Reviews and approves documents
John	Employee / Reader	Reads and acknowledges documents
These are all users of GAXIS-Lumen.
Document Owner, Releaser and Reader are not separate applications. They are responsibilities assigned to users within the same product.
3. What will the product look like?
Admin's experience
Admin logs in and sees a dashboard containing user management, documents, publication status, access grants and audit activity.
The Admin can register Sarah, Michael and John, assign their roles and reader classes, and manage the document access rules.
For external contractors, the Admin can grant access to specific approved documents for a limited period.
Sarah's experience — Document Owner
Sarah logs in and sees the document library and a Prepare Document screen.
She prepares the Employee Code of Conduct, selects its document family, classification and intended readers, uploads the file and submits it for release.
The document is not immediately published.
Michael's experience — Releaser
Michael logs in and sees the Release Queue.
He reviews the document prepared by Sarah and either releases it or returns it for correction.
Sarah cannot release her own prepared document. This separation is an essential product rule.
John's experience — Employee
John logs in and sees My Reading and the Document Library.
He opens the approved Employee Code of Conduct, reads it, and confirms acknowledgement.
The system records that John acknowledged the specific approved version, along with the date and time.
If that policy is revised later, John receives a new acknowledgement obligation for the updated version.
4. Complete product workflow
Admin
Registers employees, assigns responsibilities and configures access
Document Owner
Prepares the document and submits it
Document Releaser
Reviews and publishes the approved version
Document Library
Makes the approved version available to eligible readers
Employee / Contractor
Opens permitted documents and completes required reading
GAXIS-Lumen
Records access, version-specific acknowledgements and audit evidence
Management
Monitors reading completion, publication and compliance

5. What happens in each product module?
Module	Actual user experience
Dashboard	See assigned reading, publication activity and relevant summaries
User Management	Admin registers users and assigns responsibilities
Roles & Reader Classes	Admin configures what users can do and which access rules apply
Document Library	Browse and search approved documents the user may access
Prepare Document	Owner prepares a document for controlled publication
Release Queue	Authorised releaser reviews documents before publication
My Reading	Employee sees required documents and completion progress
Document Reader	Read approved documents with watermarks and accessibility tools
Media Library	Watch safety videos and other approved training media
External Grants	Give contractors or reviewers document-specific, expiring access
Team Completion	Managers and HCM monitor assigned reading
Audit Query	Retrieve records of required reading, document opens and acknowledgements
6. What happens when a document is updated?
This is an important part of the product.
Suppose John acknowledged Safety Policy V1.0.
Three months later, the owner updates the policy.
Safety Policy V1.0
Superseded

The previous version remains available as controlled historical evidence.

Safety Policy V2.0
Approved & Current

The revised version is released with a summary of what changed.

John's My Reading
V1.0 acknowledgement
Completed

V2.0 acknowledgement
Required


John must acknowledge V2.0. His previous acknowledgement of V1.0 is preserved.
This means GREEN can later prove which version John had acknowledged at a particular time.
7. How does the product work for contractors?
Suppose GREEN hires David, an external contractor.
David must read the Site Safety Procedure but should not see confidential HR policies or unrelated engineering documents.
The product works as follows:
1. Admin registers David as a contractor.
2. Admin gives David the ability to read documents.
3. An authorised person grants access specifically to the Site Safety Procedure.
4. The grant has an expiry date, no more than 90 days ahead.
5. David signs in using an email login link.
6. David sees only documents covered by his valid grants.
7. When the grant expires, access is refused automatically.
The role tells the system what David can do. His reader class and explicit grants determine which documents he can access.
8. What makes GAXIS-Lumen different?
GAXIS-Lumen is not intended to replace Word, Google Docs or other tools used to write documents.
Its purpose is to control approved information after it has been prepared.
The BRD also specifies accessible reading, audio/video support, captions, seven-year audit retention and compliance reporting. AI question answering is not part of the first release.
9. What does a successful product look like?
Imagine an auditor asks GREEN:
Show me which Site Safety Procedure John was required to read on 15 October, which version he opened, and whether he acknowledged it.

GREEN opens GAXIS-Lumen's Audit Query screen, selects John and the relevant date range, and retrieves the evidence.
That is the central outcome of the product.
The BRD requires this evidence query to return a complete result within 10 seconds.

What this means for backend development
Before writing code, the developer should understand these six business journeys:
1. User onboarding: Admin registers a user and assigns their access responsibilities.
2. Document publication: Owner prepares a document; another authorised person releases it.
3. Document discovery: A reader sees only documents they are permitted to access.
4. Mandatory reading: Users read and acknowledge assigned versions.
5. Document revision: Updated versions replace the current version and trigger reacknowledgement.
6. Audit evidence: Management retrieves reliable reading, access and acknowledgement history.