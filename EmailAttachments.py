#imports for evtx
from java.lang import Class
from java.lang import System
from java.sql import DriverManager, SQLException
from java.util.logging import Level
from java.io import File

import jarray
import inspect
import os
import subprocess
import re
from java.lang import System
from java.util.logging import Level
from org.sleuthkit.datamodel import SleuthkitCase
from org.sleuthkit.datamodel import ReadContentInputStream
from org.sleuthkit.datamodel import BlackboardArtifact
from org.sleuthkit.datamodel import BlackboardAttribute
from org.sleuthkit.datamodel.blackboardutils.attributes import MessageAttachments
from org.sleuthkit.autopsy.ingest import IngestModule
from org.sleuthkit.autopsy.ingest.IngestModule import IngestModuleException
from org.sleuthkit.autopsy.ingest import DataSourceIngestModule
from org.sleuthkit.autopsy.ingest import IngestModuleFactoryAdapter
from org.sleuthkit.autopsy.ingest import GenericIngestModuleJobSettings
from org.sleuthkit.autopsy.ingest import IngestModuleIngestJobSettingsPanel
from org.sleuthkit.autopsy.ingest import IngestMessage
from org.sleuthkit.autopsy.ingest import IngestServices
from org.sleuthkit.autopsy.ingest import ModuleDataEvent
from org.sleuthkit.autopsy.coreutils import Logger
from org.sleuthkit.autopsy.coreutils import PlatformUtil
from org.sleuthkit.autopsy.casemodule import Case
from org.sleuthkit.autopsy.casemodule.services import Services
from org.sleuthkit.autopsy.casemodule.services import FileManager
from org.sleuthkit.autopsy.datamodel import ContentUtils
from org.sleuthkit.datamodel.blackboardutils.attributes import BlackboardJsonAttrUtil

# Factory that defines the name and details of the module and allows Autopsy
# to create instances of the modules that will do the anlaysis.
# TODO: Rename this to something more specific.  Search and replace for it because it is used a few times
class ArtifactGroupFactory(IngestModuleFactoryAdapter):

    # TODO: give it a unique name.  Will be shown in module list, logs, etc.
    moduleName = "Mail File and URL Attachments (CKC)"

    def getModuleDisplayName(self):
        return self.moduleName

    # TODO: Give it a description
    def getModuleDescription(self):
        return "Groups artifacts by CKC phase"

    def getModuleVersionNumber(self):
        return "1.0"

    def isDataSourceIngestModuleFactory(self):
        return True

    def createDataSourceIngestModule(self, ingestOptions):
        return ArtifactGroup()



# File-level ingest module.  One gets created per thread.
# TODO: Rename this to something more specific. Could just remove "Factory" from above name.
# Looks at the attributes of the passed in file.
class ArtifactGroup(DataSourceIngestModule):

    _logger = Logger.getLogger(ArtifactGroupFactory.moduleName)

    def log(self, level, msg):
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)
    def __init__(self):
        self.context = None

    # Where any setup and configuration is done
    # 'context' is an instance of org.sleuthkit.autopsy.ingest.IngestJobContext.
    # See: http://sleuthkit.org/autopsy/docs/api-docs/4.6.0/classorg_1_1sleuthkit_1_1autopsy_1_1ingest_1_1_ingest_job_context.html
    # TODO: Add any setup code that you need here.
    def startUp(self, context):
        self.context = context

    pass

    # Where the analysis is done.  Each file will be passed into here.
    # The 'file' object being passed in is of type org.sleuthkit.datamodel.AbstractFile.
    # See: http://www.sleuthkit.org/sleuthkit/docs/jni-docs/4.6.0/classorg_1_1sleuthkit_1_1datamodel_1_1_abstract_file.html
    # TODO: Add your analysis code in here.
    def process(self, dataSource, progressBar):

        progressBar.switchToIndeterminate()
        modulename = ArtifactGroupFactory.moduleName
        # create sluethkit case
        skCase = Case.getCurrentCase().getSleuthkitCase()
        # get the artifact_type_id of the TSK_EMAIL_MSG
        emailartifactID = skCase.getArtifactTypeID("TSK_EMAIL_MSG")
        # get all email artifacts based on the artifact_type_id
        emailArtifacts = skCase.getBlackboardArtifacts(emailartifactID)

        # for each email
        for email in emailArtifacts:
            # get all attributes of the email
            emailAttributes = email.getAttributes()
            # for each attribute of the email
            for attribute in emailAttributes:
                # search for urls in the plain and html part of an email
                if (attribute.getAttributeType().getTypeName() == "TSK_EMAIL_CONTENT_PLAIN" or attribute.getAttributeType().getTypeName() == "TSK_EMAIL_CONTENT_HTML"):
                    string = attribute.getValueString()
                    self.log(Level.INFO, "STRING=======>: " + string)
                    # with valid conditions for urls in string
                    string = "" + string + ""
                    urls = re.findall(r'(https?://\S+)', string)
                    for url in urls:
                        url = url.split('"')
                        url = url[0].split("'")
                        self.log(Level.INFO, "URL=======>: " + url[0])
                        try:
                            skCase.addArtifactType("TSK_CKC_EMAIL_ATTACHMENTS", "CKC Delivery Email Attachments")
                        except:
                            # if the artifact type already exists do nothing
                            self.log(Level.INFO, "TSK_CKC_EMAIL_ATTACHMENTS artifact already exists")

                        # first we need to get the IDs of the TSK_CKC_EMAIL_ATTACHMENTS and of the attributes of the TSK_CKC_EMAIL_ATTACHMENTS
                        artID_CKC_EMAIL_ATTACHMENTS = skCase.getArtifactTypeID("TSK_CKC_EMAIL_ATTACHMENTS")
                        attID_TSK_EMAIL_TO = skCase.getAttributeType("TSK_EMAIL_TO")
                        attID_TSK_EMAIL_FROM = skCase.getAttributeType("TSK_EMAIL_FROM")
                        attID_TSK_DATETIME_RCVD = skCase.getAttributeType("TSK_DATETIME_RCVD")

                        try:
                            attID_TSK_ATTACHMENTS = skCase.addArtifactAttributeType("TSK_CKC_ATTACHMENT_FILE_NAME",
                                                                                    BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING,
                                                                                    "Attachment name")
                        except:
                            self.log(Level.INFO, "Attributes Creation Error, Event Log File Name. ==> ")

                            # get the obj_id -> this is the ID of the Source file
                        sourceFileID = email.getObjectID()
                        # get the actual file using its obj_id
                        sourceFile = skCase.getAbstractFileById(sourceFileID)
                        try:
                            art = sourceFile.newArtifact(artID_CKC_EMAIL_ATTACHMENTS)
                            art.addAttributes((
                                (BlackboardAttribute(attID_TSK_EMAIL_TO, ArtifactGroupFactory.moduleName,
                                                     email.getAttribute(attID_TSK_EMAIL_TO).getValueString())), \
                                (BlackboardAttribute(attID_TSK_EMAIL_FROM, ArtifactGroupFactory.moduleName,
                                                     email.getAttribute(attID_TSK_EMAIL_FROM).getValueString())), \
                                (BlackboardAttribute(attID_TSK_ATTACHMENTS, ArtifactGroupFactory.moduleName,
                                                     url[0])), \
                                (BlackboardAttribute(attID_TSK_DATETIME_RCVD, ArtifactGroupFactory.moduleName,
                                                     email.getAttribute(attID_TSK_DATETIME_RCVD).getValueLong()))
                            ))
                        except:
                            self.log(Level.INFO, "Artifact cannot be created. Moved to next.")

                    # if the attribute is a TSK_ATTACHMENTS; i.e., an email attachment or a URL attachment
                if(attribute.getAttributeType().getTypeName() == "TSK_ATTACHMENTS"):
                    # convert the attribute to MessageAttachments object
                    messageAttachments = BlackboardJsonAttrUtil.fromAttribute(attribute, MessageAttachments)
                    # get the attached files - i.e., the files attached to the email
                    attachedFiles = messageAttachments.getFileAttachments()
                    # for each attached file
                    for attachedFile in attachedFiles:
                        # print the path of the attachment file
                        self.log(Level.INFO, "==========>: " + str(attachedFile.getPathName()))
                        attachmentData = str(attachedFile.getPathName()).split("/")
                        Filename = attachmentData[-1]
                        self.log(Level.INFO, "FILENAME==========>: " + Filename)

                        # create new artifact type
                        try:
                            skCase.addArtifactType("TSK_CKC_EMAIL_ATTACHMENTS", "CKC Delivery Email Attachments")
                        except:
                            # if the artifact type already exists do nothing
                            self.log(Level.INFO, "TSK_CKC_EMAIL_ATTACHMENTS artifact already exists")

                        # first we need to get the IDs of the TSK_CKC_EMAIL_ATTACHMENTS and of the attributes of the TSK_CKC_EMAIL_ATTACHMENTS
                        artID_CKC_EMAIL_ATTACHMENTS = skCase.getArtifactTypeID("TSK_CKC_EMAIL_ATTACHMENTS")
                        attID_TSK_EMAIL_TO = skCase.getAttributeType("TSK_EMAIL_TO")
                        attID_TSK_EMAIL_FROM = skCase.getAttributeType("TSK_EMAIL_FROM")
                        attID_TSK_DATETIME_RCVD = skCase.getAttributeType("TSK_DATETIME_RCVD")

                        try:
                            attID_TSK_ATTACHMENTS = skCase.addArtifactAttributeType("TSK_CKC_ATTACHMENT_FILE_NAME",
                                                                          BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING,
                                                                          "Attachment name")
                        except:
                            self.log(Level.INFO, "Attributes Creation Error, Event Log File Name. ==> ")

                        # get the obj_id -> this is the ID of the Source file
                        sourceFileID = email.getObjectID()
                        # get the actual file using its obj_id
                        sourceFile = skCase.getAbstractFileById(sourceFileID)
                        try:
                            art = sourceFile.newArtifact(artID_CKC_EMAIL_ATTACHMENTS)
                            art.addAttributes((
                                (BlackboardAttribute(attID_TSK_EMAIL_TO, ArtifactGroupFactory.moduleName,
                                                     email.getAttribute(attID_TSK_EMAIL_TO).getValueString())), \
                                (BlackboardAttribute(attID_TSK_EMAIL_FROM, ArtifactGroupFactory.moduleName,
                                                     email.getAttribute(attID_TSK_EMAIL_FROM).getValueString())), \
                                (BlackboardAttribute(attID_TSK_ATTACHMENTS, ArtifactGroupFactory.moduleName,
                                                    Filename)), \
                                 (BlackboardAttribute(attID_TSK_DATETIME_RCVD, ArtifactGroupFactory.moduleName,
                                                     email.getAttribute(attID_TSK_DATETIME_RCVD).getValueLong()))
                            ))
                        except:
                            self.log(Level.INFO, "Artifact cannot be created. Moved to next.")

        return IngestModule.ProcessResult.OK

    def shutDown(self):
        # As a final part of this example, we'll send a message to the ingest inbox with the number of files found (in this thread)
        message = IngestMessage.createMessage(
            IngestMessage.MessageType.DATA, ArtifactGroupFactory.moduleName,
            str(self.filesFound) + " files found")
        ingestServices = IngestServices.getInstance().postMessage(message)